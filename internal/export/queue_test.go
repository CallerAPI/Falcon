package export

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

// A carrier ingress writes far more than 100 events per 30 s. One tick must
// drain the backlog in batches instead of leaving it to grow for the life
// of the process.
func TestDrainClearsABacklogInOneTick(t *testing.T) {
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	const backlog = 1234
	for i := 0; i < backlog; i++ {
		if _, err := db.Insert(ctx, store.Event{ReceivedAt: time.Now(), Action: score.ActionAllow, From: "+13125550100", To: "+14155550100", CallID: "c"}); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	q := &Queue{Store: db, CallerAPI: &CallerAPI{BaseURL: srv.URL, InstallID: "i", Version: "t", HMACKey: []byte("k")}}
	q.drain(ctx)
	left, err := db.Unexported(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("%d events still unexported after one tick", len(left))
	}
	if got := calls.Load(); got != 13 {
		t.Fatalf("expected 13 batches of 100, got %d", got)
	}

	// A failing endpoint stops the tick after one attempt, so a dead
	// upstream does not cost 50 requests every 30 s.
	for i := 0; i < 250; i++ {
		_, _ = db.Insert(ctx, store.Event{ReceivedAt: time.Now(), Action: score.ActionAllow, From: "+13125550100", To: "+14155550100", CallID: "c"})
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer bad.Close()
	q.CallerAPI.BaseURL = bad.URL
	calls.Store(0)
	q.drain(ctx)
	if calls.Load() != 1 {
		t.Fatalf("a failing upstream must be tried once per tick, got %d", calls.Load())
	}
}
