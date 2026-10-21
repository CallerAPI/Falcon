package export

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/share"
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
		if _, err := db.Insert(ctx, store.Event{ReceivedAt: time.Now(), Action: score.ActionReject, From: "+13125550100", To: "+14155550100", CallID: "c"}); err != nil {
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
		_, _ = db.Insert(ctx, store.Event{ReceivedAt: time.Now(), Action: score.ActionReject, From: "+13125550100", To: "+14155550100", CallID: "c"})
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

func seedEvents(t *testing.T, n int) store.Store {
	t.Helper()
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for i := 0; i < n; i++ {
		if _, err := db.Insert(context.Background(), store.Event{ReceivedAt: time.Now(), Action: score.ActionReject, From: "+13125550100", To: "+14155550100", CallID: "c"}); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// A throttled install waits as long as CallerAPI asks. It does not post
// again on the next tick.
func TestRetryAfterHoldsTheNextPost(t *testing.T) {
	db := seedEvents(t, 10)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	q := &Queue{Store: db, CallerAPI: &CallerAPI{BaseURL: srv.URL, InstallID: "i", Version: "t", HMACKey: []byte("k")}, now: func() time.Time { return now }}
	ctx := context.Background()

	q.drain(ctx)
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
	now = now.Add(119 * time.Second)
	q.drain(ctx)
	if calls.Load() != 1 {
		t.Fatal("posted again before Retry-After ran out")
	}
	now = now.Add(30 * time.Second)
	q.drain(ctx)
	if calls.Load() != 2 {
		t.Fatalf("calls = %d after the wait, want 2", calls.Load())
	}
	if left, _ := db.Unexported(ctx, 100); len(left) != 0 {
		t.Fatalf("%d events left after the retry", len(left))
	}
}

// With no Retry-After the wait doubles from one interval and stops at
// maxBackoff, with up to 20% jitter.
func TestBackoffDoublesToTheCap(t *testing.T) {
	q := &Queue{Interval: 30 * time.Second}
	plain := errors.New("connection refused")
	for failures, want := range map[int]time.Duration{1: 30 * time.Second, 2: time.Minute, 3: 2 * time.Minute, 6: maxBackoff, 40: maxBackoff} {
		q.apiFailures = failures
		got := q.backoff(plain)
		if got > want || got < want-want/5 {
			t.Fatalf("failure %d: wait %s, want %s minus up to 20%%", failures, got, want)
		}
	}
	q.apiFailures = 1
	got := q.backoff(&HTTPError{Status: "429 Too Many Requests", RetryAfter: 90 * time.Second})
	if got < 90*time.Second || got > 108*time.Second {
		t.Fatalf("Retry-After 90s gave %s", got)
	}
	got = q.backoff(&HTTPError{Status: "429 Too Many Requests", RetryAfter: 24 * time.Hour})
	if got > maxBackoff+maxBackoff/5 {
		t.Fatalf("Retry-After of a day gave %s, cap is %s", got, maxBackoff)
	}
}

// Clean calls leave the host as hourly counts. Calls with a signal leave
// as rows. The hour is sent once.
func TestCleanCallsTravelAsCounts(t *testing.T) {
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	hour := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	insert := func(ev store.Event) {
		t.Helper()
		if ev.ReceivedAt.IsZero() {
			ev.ReceivedAt = hour.Add(10 * time.Minute)
		}
		if ev.Action == "" {
			ev.Action = score.ActionAllow
		}
		if _, err := db.Insert(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 6; i++ {
		insert(store.Event{From: "+13125550100", To: fmt.Sprintf("+1415555010%d", i), CallID: "clean", Direction: "inbound",
			SignerSPC: "567J", SignerName: "Graystone Gateway LLC", Verstat: "TN-Validation-Passed", Fingerprint: "aaaa1111", UserAgent: "Graystone-SBC/1.0",
			Shaken: json.RawMessage(`{"present":true,"verstat":"TN-Validation-Passed"}`)})
	}
	insert(store.Event{From: "+13125550188", To: "+14155550199", Action: score.ActionReject, CallID: "bad"})
	insert(store.Event{From: "+13125550177", To: "+14155550198", Honeypot: true, CallID: "trap"})
	insert(store.Event{From: "+14155550111", To: "+13125550100", Direction: "outbound", CallID: "out"})
	insert(store.Event{From: "+14155550123", To: "+14155550123", CallID: "spoof"})
	insert(store.Event{From: "+13125550166", To: "+14155550197", SignerSPC: "999Z", CallID: "switch",
		Shaken: json.RawMessage(`{"source":"switch","attest":"A"}`)})

	var posts []telemetryRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req telemetryRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		posts = append(posts, req)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	now := hour.Add(2 * time.Hour)
	q := &Queue{Store: db, CallerAPI: &CallerAPI{BaseURL: srv.URL, InstallID: "i", Version: "t", HMACKey: []byte("k")}, now: func() time.Time { return now }}
	q.drain(ctx)

	var rows []string
	rollups := map[string]share.Rollup{}
	for _, p := range posts {
		for _, ev := range p.Events {
			rows = append(rows, ev.CallID+":"+ev.Kind)
		}
		for _, r := range p.Rollups {
			rollups[r.Dim+":"+r.Key] = r
		}
	}
	if strings.Join(rows, ",") != "bad:evidence,trap:evidence" {
		t.Fatalf("rows sent: %v", rows)
	}
	// Six clean calls, the call that shows the subscriber's own number, and
	// the call the switch signed. Not the outbound call.
	if r := rollups["install:"]; r.Calls != 8 || r.Hour != "2026-10-21T09:00:00Z" {
		t.Fatalf("install bucket %+v", r)
	}
	if r := rollups["caller:+13125550100"]; r.Calls != 6 || r.Callees != 6 || r.SPC != "567J" || r.Fingerprint != "aaaa1111" {
		t.Fatalf("caller bucket %+v", r)
	}
	if r := rollups["signer:567J"]; r.Calls != 6 || r.Verified != 6 || r.Label != "Graystone Gateway LLC" {
		t.Fatalf("signer bucket %+v", r)
	}
	if _, ok := rollups["signer:999Z"]; ok {
		t.Fatal("a signer the switch reported was counted")
	}
	for _, key := range []string{"caller:+14155550111", "caller:+14155550123"} {
		if _, ok := rollups[key]; ok {
			t.Fatalf("%s left the host", key)
		}
	}

	posts = nil
	q.drain(ctx)
	if len(posts) != 0 {
		t.Fatalf("the hour was sent again: %d posts", len(posts))
	}

	insert(store.Event{From: "+13125550100", To: "+14155550109", CallID: "late", ReceivedAt: hour.Add(time.Hour + 5*time.Minute)})
	q.CleanEvery = 1
	now = now.Add(time.Hour)
	q.drain(ctx)
	var kinds []string
	for _, p := range posts {
		for _, ev := range p.Events {
			kinds = append(kinds, ev.CallID+":"+ev.Kind)
		}
	}
	if strings.Join(kinds, ",") != "late:sample" {
		t.Fatalf("with every clean call sampled: %v", kinds)
	}
}

func TestRetryAfterHeader(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{
		"":                              0,
		"60":                            time.Minute,
		" 5 ":                           5 * time.Second,
		"-3":                            0,
		"soon":                          0,
		"Wed, 21 Oct 2026 12:02:00 GMT": 2 * time.Minute,
		"Wed, 21 Oct 2026 11:00:00 GMT": 0,
	} {
		if got := retryAfter(in, now); got != want {
			t.Fatalf("retryAfter(%q) = %s, want %s", in, got, want)
		}
	}
}
