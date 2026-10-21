package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

func TestTelemetryFollowsTheEnvironmentOnly(t *testing.T) {
	srv, db := newTestServer(t)
	srv.Cfg.Share = true
	ctx := context.Background()

	if !srv.Sharing(ctx) {
		t.Fatal("sharing must be on when FALCON_SHARE is true")
	}
	// An install that opted out in an older dashboard shares again.
	_ = db.KVSet(ctx, "share_opt_out", "1")
	if !srv.Sharing(ctx) {
		t.Fatal("an old dashboard opt-out turned telemetry off")
	}
	// A dashboard client cannot turn it off.
	if w := do(t, srv, http.MethodPut, "/v1/settings", map[string]bool{"share_telemetry": false}); w.Code != 200 {
		t.Fatalf("settings put: %d %s", w.Code, w.Body.String())
	}
	if !srv.Sharing(ctx) {
		t.Fatal("a settings call turned telemetry off")
	}
	w := do(t, srv, http.MethodGet, "/v1/status", nil)
	var st struct {
		Share struct {
			Configured bool     `json:"configured"`
			Effective  bool     `json:"effective"`
			Redacted   []string `json:"redacted"`
		} `json:"share"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if !st.Share.Configured || !st.Share.Effective || len(st.Share.Redacted) == 0 {
		t.Fatalf("status share = %+v", st.Share)
	}
	srv.Cfg.Share = false
	if srv.Sharing(ctx) {
		t.Fatal("FALCON_SHARE=false must turn telemetry off")
	}
}

func TestModeAndFASModeChangeAtRuntime(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.Cfg.Mode, srv.Cfg.FASMode = "enforce", "monitor"
	ctx := context.Background()
	if srv.Mode(ctx) != "enforce" || srv.FASMode(ctx) != "monitor" {
		t.Fatalf("defaults %s %s", srv.Mode(ctx), srv.FASMode(ctx))
	}
	if w := do(t, srv, http.MethodPut, "/v1/settings", map[string]string{"mode": "monitor", "fas_mode": "enforce"}); w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	if srv.Mode(ctx) != "monitor" || srv.FASMode(ctx) != "enforce" {
		t.Fatalf("after save %s %s", srv.Mode(ctx), srv.FASMode(ctx))
	}
	if w := do(t, srv, http.MethodPut, "/v1/settings", map[string]string{"mode": "off"}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad mode accepted: %d", w.Code)
	}
}

func TestSettingsOverrideEnvAndValidate(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.Cfg.RetentionDays = 30
	srv.Cfg.RawSIPRetentionDays = 7

	w := do(t, srv, http.MethodGet, "/v1/settings", nil)
	var got struct {
		Effective Settings `json:"effective"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Effective.RetentionDays != 30 || got.Effective.RawSIPRetentionDays != 7 {
		t.Fatalf("defaults: %+v", got.Effective)
	}

	w = do(t, srv, http.MethodPut, "/v1/settings", map[string]int{"retention_days": 90, "raw_sip_retention_days": 2})
	if w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	r := srv.Retention()
	if r.Events != 90*24*time.Hour || r.RawSIP != 48*time.Hour {
		t.Fatalf("retention after save: %+v", r)
	}

	for _, bad := range []map[string]int{{"retention_days": 0}, {"retention_days": 5000}, {"raw_sip_retention_days": 400}} {
		if w := do(t, srv, http.MethodPut, "/v1/settings", bad); w.Code != http.StatusBadRequest {
			t.Fatalf("%v accepted with %d", bad, w.Code)
		}
	}
}

func TestScrubKeepsDecisionAndDropsRawSIP(t *testing.T) {
	_, db := newTestServer(t)
	ctx := context.Background()
	old := time.Now().Add(-10 * 24 * time.Hour)
	id, err := db.Insert(ctx, store.Event{ReceivedAt: old, Action: score.ActionReject, RiskScore: 90, From: "+14155550100", RawSIP: "INVITE sip:x SIP/2.0\r\nFrom: <sip:+14155550100@a>\r\n"})
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := db.Insert(ctx, store.Event{ReceivedAt: time.Now(), Action: score.ActionAllow, RiskScore: 5, From: "+14155550101", RawSIP: "INVITE fresh"})

	n, err := db.ScrubRawSIP(ctx, time.Now().Add(-7*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("scrub n=%d err=%v", n, err)
	}
	ev, _ := db.Get(ctx, id)
	if ev.RawSIP != "" || ev.Action != score.ActionReject || ev.From != "+14155550100" {
		t.Fatalf("old event: %+v", ev)
	}
	ev2, _ := db.Get(ctx, fresh)
	if ev2.RawSIP != "INVITE fresh" {
		t.Fatalf("fresh event lost raw sip: %+v", ev2)
	}
	if n, _ := db.ScrubRawSIP(ctx, time.Now().Add(-7*24*time.Hour)); n != 0 {
		t.Fatalf("second scrub touched %d rows", n)
	}
}

func TestBridgeCarryChangesAtRuntime(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()
	if srv.CarryAll(ctx) {
		t.Fatal("the default must carry suspicious calls only")
	}
	if w := do(t, srv, http.MethodPut, "/v1/settings", map[string]string{"bridge_carry": "all"}); w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	if !srv.CarryAll(ctx) {
		t.Fatal("bridge_carry all did not stick")
	}
	if w := do(t, srv, http.MethodPut, "/v1/settings", map[string]string{"bridge_carry": "everything"}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad carry accepted: %d", w.Code)
	}
}
