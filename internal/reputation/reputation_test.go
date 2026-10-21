package reputation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/identity"
	"github.com/callerapi/falcon/internal/store"
)

// A keyed install that does not share fetches the feed with its key.
func TestKeyedInstallFetchesTheFeed(t *testing.T) {
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key, err := identity.Load(context.Background(), db, "inst")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, _, err := identity.Verify(r, nil, time.Minute); err != nil || id != "inst" {
			t.Errorf("signature: %q %v", id, err)
		}
		if r.Header.Get("X-Auth") != "k-1" {
			t.Errorf("X-Auth = %q", r.Header.Get("X-Auth"))
		}
		_ = json.NewEncoder(w).Encode(Feed{Signers: []Signer{{SPC: "567J", Installs: 3, Score: 80}}})
	}))
	defer srv.Close()
	tbl := &Table{BaseURL: srv.URL, Key: key, APIKey: "k-1", Enabled: func(context.Context) bool { return true }}
	if err := tbl.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s, ok := tbl.Signer("567J"); !ok || s.Score != 80 {
		t.Fatalf("signer %+v %v", s, ok)
	}
}

func TestNoShareAndNoKeyFetchesNothing(t *testing.T) {
	db, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "r.db"))
	defer db.Close()
	key, _ := identity.Load(context.Background(), db, "inst")
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	tbl := &Table{BaseURL: srv.URL, Key: key, Enabled: func(context.Context) bool { return false }}
	if err := tbl.Load(context.Background()); err != nil || called || tbl.Status().Error == "" {
		t.Fatalf("err %v, called %v, status %+v", err, called, tbl.Status())
	}
}
