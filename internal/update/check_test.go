package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/store"
)

func TestNewer(t *testing.T) {
	if !Newer("1.2.3", "1.2.4") {
		t.Fatal("patch")
	}
	if !Newer("1.2.3", "v1.3.0") {
		t.Fatal("minor")
	}
	if Newer("1.2.3", "1.2.3") || Newer("1.2.3", "1.2.2") || Newer("dev", "9.0.0") || Newer("1.2.3", "") {
		t.Fatal("not newer")
	}
}

func TestReleaseCheckAlertsOnceAndIgnoresDev(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("User-Agent") != "falcon/1.0.0" {
			t.Errorf("user agent %s", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0","html_url":"https://example.com/falcon/releases/tag/v1.2.0"}`))
	}))
	defer srv.Close()

	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	watcher := &alerts.Watcher{Sources: alerts.Sources{
		Store:      db,
		Thresholds: func(context.Context) alerts.Thresholds { return alerts.Thresholds{} },
	}}
	var seen Status
	c := &Checker{
		Version: "1.0.0", URL: srv.URL, HTTP: srv.Client(), Store: db, Alerts: watcher,
		OnStatus: func(st Status) { seen = st },
	}
	c.once(context.Background())
	c.once(context.Background())
	if !seen.Newer || seen.Latest != "1.2.0" {
		t.Fatalf("status %+v", seen)
	}
	rows, err := db.Alerts(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Key != "release:1.2.0" {
		t.Fatalf("alerts %+v", rows)
	}
	if hits != 2 {
		t.Fatalf("hits %d", hits)
	}

	devHits := 0
	devSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { devHits++ }))
	defer devSrv.Close()
	(&Checker{Version: "dev", URL: devSrv.URL, HTTP: devSrv.Client()}).Run(context.Background())
	if devHits != 0 {
		t.Fatalf("dev build contacted the release server %d times", devHits)
	}
}

func TestReleaseCheckKeepsTheCurrentTagOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer srv.Close()
	called := false
	c := &Checker{Version: "1.0.0", URL: srv.URL, HTTP: srv.Client(), OnStatus: func(Status) { called = true }}
	c.once(context.Background())
	if called {
		t.Fatal("failure must not publish a release status")
	}
}
