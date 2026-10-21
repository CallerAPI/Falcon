package compliance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/identity"
	"github.com/callerapi/falcon/internal/store"
)

func TestSourceSignsAndHonorsETag(t *testing.T) {
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key, err := identity.Load(context.Background(), db, "install-1")
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != Path {
			t.Errorf("path %s", r.URL.Path)
		}
		if id, _, err := identity.Verify(r, nil, time.Minute); err != nil || id != "install-1" {
			t.Errorf("signature: %q %v", id, err)
		}
		if got := r.Header.Get("X-Auth"); got != "k-1" {
			t.Errorf("X-Auth = %q, want the API key", got)
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_ = json.NewEncoder(w).Encode(testList())
	}))
	defer srv.Close()
	src := &Source{BaseURL: srv.URL, Key: key, APIKey: "k-1"}
	l, tag, notModified, err := src.Fetch(context.Background(), "")
	if err != nil || notModified || tag != `"v1"` || len(l.Providers) != len(testList().Providers) {
		t.Fatalf("first fetch: %d providers, tag %q, notModified %v, err %v", len(l.Providers), tag, notModified, err)
	}
	if _, _, notModified, err := src.Fetch(context.Background(), `"v1"`); err != nil || !notModified {
		t.Fatalf("second fetch: notModified %v, err %v", notModified, err)
	}
	if calls != 2 {
		t.Fatalf("%d calls", calls)
	}
}

func TestSourceExplainsAccess(t *testing.T) {
	db, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "k.db"))
	defer db.Close()
	key, _ := identity.Load(context.Background(), db, "install-2")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	_, _, _, err := (&Source{BaseURL: srv.URL, Key: key}).Fetch(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "shared telemetry") {
		t.Fatalf("err %v", err)
	}
}

// An autopilot fed from a file saves the list and starts from it after a
// restart with no source.
func TestFileSourceAndRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fcc.json")
	b, _ := json.Marshal(testList())
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	rig := newRig(t)
	rig.a.Source = File{Path: path}
	rig.a.Sync(context.Background())
	if st := rig.a.Status(); st.Providers != len(testList().Providers) || st.Error != "" {
		t.Fatalf("status %+v", st)
	}
	_, tag, notModified, err := File{Path: path}.Fetch(context.Background(), "")
	if err != nil || notModified {
		t.Fatal(err)
	}
	if _, _, notModified, _ := (File{Path: path}).Fetch(context.Background(), tag); !notModified {
		t.Fatal("an unchanged file was read again")
	}
	restarted := &Autopilot{Store: rig.db}
	restarted.loadSaved(context.Background())
	if restarted.currentIndex() == nil || restarted.currentIndex().Count() != len(testList().Providers) {
		t.Fatal("the saved list did not load after a restart")
	}
}
