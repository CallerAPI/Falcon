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

func TestMonitorRecordsTheDecisionAndContinues(t *testing.T) {
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := &Server{
		Cfg: config.Config{FailOpen: true, Token: "secret", StoreRawSIP: true, Mode: config.ModeMonitor},
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
	if res.Action != score.ActionAllow || res.Headers["X-Falcon-Monitor"] != "reject" {
		t.Fatalf("switch saw %+v", res)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		events, err := db.Recent(context.Background(), 5)
		if err == nil && len(events) == 1 {
			if events[0].Action != score.ActionReject {
				t.Fatalf("stored %s", events[0].Action)
			}
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

// An adapter that sends no Content-Type says nothing about the offer. A raw
// INVITE without a body has none.
func TestScreenOfferUnknownIsNotMissing(t *testing.T) {
	srv, _ := newTestServer(t)
	noOffer := func(res score.Result) bool {
		for _, r := range res.Reasons {
			if r.Code == "invite_no_sdp" {
				return true
			}
		}
		return false
	}
	headers := func(callID string, extra map[string]string) map[string]string {
		h := map[string]string{
			"From": "<sip:+14155550100@ex>;tag=1", "To": "<sip:+15551212@ex>", "Call-ID": callID,
			"User-Agent": "FreeSWITCH", "Max-Forwards": "70",
		}
		for k, v := range extra {
			h[k] = v
		}
		return h
	}
	invite := func(h map[string]string) map[string]any {
		return map[string]any{"switch": "fs", "source_ip": "198.51.100.20", "method": "INVITE", "request_uri": "sip:+15551212@ex", "headers": h}
	}
	if res := screenJSON(t, srv, invite(headers("o1", nil))); noOffer(res) {
		t.Fatalf("a header map without Content-Type got invite_no_sdp: %+v", res.Reasons)
	}
	if res := screenJSON(t, srv, invite(headers("o2", map[string]string{"Content-Type": "application/sdp"}))); noOffer(res) {
		t.Fatalf("an offer got invite_no_sdp: %+v", res.Reasons)
	}
	if res := screenJSON(t, srv, invite(headers("o3", map[string]string{"Content-Type": "application/isup"}))); !noOffer(res) {
		t.Fatalf("a named non-SDP body must keep invite_no_sdp: %+v", res.Reasons)
	}
	raw := "INVITE sip:+15551212@ex SIP/2.0\r\nFrom: <sip:+14155550100@ex>;tag=1\r\nTo: <sip:+15551212@ex>\r\nCall-ID: o4\r\nUser-Agent: FreeSWITCH\r\nMax-Forwards: 70\r\n\r\n"
	if res := screenJSON(t, srv, map[string]any{"switch": "fs", "source_ip": "198.51.100.20", "raw_sip": raw}); !noOffer(res) {
		t.Fatalf("a raw INVITE without a body must keep invite_no_sdp: %+v", res.Reasons)
	}
}
