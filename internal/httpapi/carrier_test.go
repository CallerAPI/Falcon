package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/voice"
)

// A wholesale ingress: one customer IP, one CLI, a call center working a
// lead list. On the trunk profile this traffic is rejected within the first
// minute. On the carrier profile it is only flagged, and hard blocks still
// reject. The ConnexCS, Kamailio, and OpenSIPS adapters all send this shape.

func carrierServer(t *testing.T, th score.Thresholds, lim score.Limits) *Server {
	t.Helper()
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := &Server{
		Cfg:       config.Config{FailOpen: true, Token: "secret", RetentionDays: 30},
		Engine:    score.NewEngine(th, lim),
		Store:     db,
		InstallID: "test",
	}
	srv.Sampler = &voice.Sampler{Store: db, Budget: voice.DefaultBudget(), Enabled: true}
	if err := srv.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return srv
}

func connexcsScreen(t *testing.T, srv *Server, cli, dest, ua string) score.Result {
	t.Helper()
	body := map[string]any{
		"switch": "connexcs", "direction": "outbound", "customer": "4242", "method": "INVITE",
		"request_uri": "sip:" + dest + "@connexcs.invalid", "source_ip": "203.0.113.9",
		"headers": map[string]string{
			"From": "<sip:" + cli + "@203.0.113.9>;tag=cx", "To": "<sip:" + dest + "@connexcs.invalid>",
			"Call-ID": "cx-" + cli + "-" + dest, "User-Agent": ua,
		},
	}
	return screenJSON(t, srv, body)
}

func dialer(t *testing.T, srv *Server, cli string, calls int) score.Result {
	t.Helper()
	var last score.Result
	for i := 0; i < calls; i++ {
		last = connexcsScreen(t, srv, cli, fmt.Sprintf("+1415555%04d", 1000+i*7), "Acme Dialer/2.1")
	}
	return last
}

func TestTrunkProfileRejectsACallCenter(t *testing.T) {
	srv := carrierServer(t, score.Thresholds{Flag: 40, Challenge: 60, Reject: 80}, score.Limits{Window: time.Minute, IP: 30, From: 20, Scan: 15})
	res := dialer(t, srv, "+13125550200", 31)
	if res.Action != score.ActionReject {
		t.Fatalf("trunk profile should reject the 31st call of a dialer, got %s %d %v", res.Action, res.RiskScore, res.Reasons)
	}
}

func TestCarrierProfileOnlyFlagsACallCenter(t *testing.T) {
	srv := carrierServer(t, score.Thresholds{Flag: 40, Challenge: 101, Reject: 101}, score.Limits{Window: time.Minute})
	res := dialer(t, srv, "+13125550200", 31)
	if res.Action != score.ActionFlag {
		t.Fatalf("carrier profile must only flag a dialer, got %s %d %v", res.Action, res.RiskScore, res.Reasons)
	}
	if res.Headers["X-Falcon-Block"] != "" {
		t.Fatalf("no hard block expected: %v", res.Headers)
	}
	for _, r := range res.Reasons {
		switch r.Code {
		case "source_invite_flood", "source_dest_scan", "from_invite_flood":
			t.Fatalf("velocity rule %s must be off on the carrier profile", r.Code)
		}
	}

	// A scanner score alone stays a flag too. Only hard blocks reject.
	res = connexcsScreen(t, srv, "+13125550201", "+14155550100", "friendly-scanner")
	if res.Action != score.ActionFlag || res.RiskScore < 90 {
		t.Fatalf("scanner on carrier profile: %s %d", res.Action, res.RiskScore)
	}
}

func TestCarrierProfileStillRejectsHardBlocks(t *testing.T) {
	srv := carrierServer(t, score.Thresholds{Flag: 40, Challenge: 101, Reject: 101}, score.Limits{Window: time.Minute})
	ctx := context.Background()
	if _, err := srv.Store.AddRule(ctx, lists.Rule{Kind: lists.Deny, Subject: lists.Number, Value: "+13125550188", Note: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.ReloadRules(ctx); err != nil {
		t.Fatal(err)
	}
	res := connexcsScreen(t, srv, "+13125550188", "+14155550100", "Acme Dialer/2.1")
	if res.Action != score.ActionReject || res.Headers["X-Falcon-Block"] != "denylist" || res.SIPStatus != 603 {
		t.Fatalf("deny rule: %s %v %d", res.Action, res.Headers, res.SIPStatus)
	}

	// A known customer presenting a number it does not own is a hard block
	// in every profile.
	w := do(t, srv, http.MethodPut, "/v1/customers", map[string]any{"id": "4242", "name": "Acme", "dids": []string{"+13125550300"}})
	if w.Code != 200 && w.Code != 201 {
		t.Fatalf("customer: %d %s", w.Code, w.Body.String())
	}
	res = connexcsScreen(t, srv, "+18005551234", "+14155550100", "Acme Dialer/2.1")
	if res.Action != score.ActionReject || res.Headers["X-Falcon-Block"] != "caller_id" {
		t.Fatalf("spoof: %s %v", res.Action, res.Headers)
	}
}
