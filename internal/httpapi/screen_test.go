package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

func TestScreenScanner(t *testing.T) {
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := &Server{
		Cfg: config.Config{FailOpen: true, Token: "secret", StoreRawSIP: true},
		Engine: score.NewEngine(
			score.Thresholds{Flag: 40, Challenge: 60, Reject: 80},
			score.Limits{Window: time.Minute, IP: 30, From: 20, Scan: 15},
		),
		Store:     db,
		InstallID: "test",
	}
	raw := `{"switch":"test","source_ip":"198.51.100.20","raw_sip":"INVITE sip:+15551212@ex SIP/2.0\r\nFrom: <sip:+14155550100@ex>;tag=1\r\nTo: <sip:+15551212@ex>\r\nCall-ID: demo\r\nUser-Agent: friendly-scanner\r\nMax-Forwards: 70\r\n\r\n"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/screen", bytes.NewBufferString(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Falcon-Token", "secret")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var res score.Result
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Action != score.ActionReject {
		t.Fatalf("action %s score %d", res.Action, res.RiskScore)
	}
	// Persist is async.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		events, err := db.Recent(context.Background(), 5)
		if err == nil && len(events) == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("event was not stored")
}

func TestScreenUnauthorized(t *testing.T) {
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := &Server{
		Cfg:    config.Config{Token: "secret"},
		Engine: score.NewEngine(score.Thresholds{Flag: 40, Challenge: 60, Reject: 80}, score.Limits{Window: time.Minute}),
		Store:  db,
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/screen", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}
