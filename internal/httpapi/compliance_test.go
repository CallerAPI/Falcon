package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/compliance"
	"github.com/callerapi/falcon/internal/config"
)

func fccList() compliance.List {
	return compliance.List{GeneratedAt: time.Now().UTC(), Providers: []compliance.Provider{
		{RMD: "RMD0000001", Name: "Northwind Voice LLC", Listed: true},
		{RMD: "RMD0000002", Name: "Graystone Gateway LLC", Order: compliance.OrderBlock, OrderDoc: "DA-26-1073", OrderDate: "2026-10-05"},
	}}
}

// The whole loop: register an upstream under a block order, see the item on
// the home screen, turn on enforcement, and its next call is rejected.
func TestFCCAutopilotEndToEnd(t *testing.T) {
	srv, db := newTestServer(t)
	srv.Cfg.FCCMode = config.ModeMonitor
	srv.Compliance = &compliance.Autopilot{Store: db, Mode: srv.FCCMode, Reload: srv.ReloadRules}
	srv.Compliance.Apply(fccList())

	if w := do(t, srv, http.MethodPost, "/v1/upstreams", map[string]any{"name": "Graystone", "rmd": "RMD12345678"}); w.Code != http.StatusBadRequest {
		t.Fatalf("a bad RMD number was accepted: %d", w.Code)
	}
	w := do(t, srv, http.MethodPost, "/v1/upstreams", map[string]any{"name": "Graystone", "rmd": "rmd 2", "ips": []string{"203.0.113.0/24"}, "contact": "noc@graystone.example"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var up upstreamView
	_ = json.Unmarshal(w.Body.Bytes(), &up)
	if up.RMD != "RMD0000002" || up.Check == nil || up.Check.Standing != compliance.Blocked || !up.Check.Confirmed {
		t.Fatalf("saved %+v check %+v", up.Upstream, up.Check)
	}

	w = do(t, srv, http.MethodGet, "/v1/overview?range=24h", nil)
	var ov struct {
		Insights []Insight `json:"insights"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &ov)
	var found *Insight
	for i := range ov.Insights {
		if strings.HasPrefix(ov.Insights[i].Key, "fcc:") {
			found = &ov.Insights[i]
		}
	}
	if found == nil || found.Severity != sevCritical || found.Action == nil || found.Action.Setting["fcc_mode"] != compliance.ModeEnforce {
		t.Fatalf("overview insights %+v", ov.Insights)
	}

	screen := func() string {
		w := do(t, srv, http.MethodPost, "/v1/screen", map[string]string{"switch": "test", "source_ip": "203.0.113.40", "raw_sip": cleanInvite("+13125550100", "Graystone-SBC/1.0")})
		var res struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &res)
		return res.Action
	}
	if got := screen(); got == "reject" {
		t.Fatal("monitor mode rejected the call")
	}
	if w := do(t, srv, http.MethodPut, "/v1/settings", map[string]string{"fcc_mode": "enforce"}); w.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", w.Code, w.Body.String())
	}
	if got := screen(); got != "reject" {
		t.Fatalf("enforce mode let the call through: %s", got)
	}

	w = do(t, srv, http.MethodGet, "/v1/compliance", nil)
	var st struct {
		Mode string `json:"mode"`
		Log  []struct {
			Action   string `json:"action"`
			Upstream string `json:"upstream"`
			Doc      string `json:"doc"`
		} `json:"log"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st.Mode != "enforce" || len(st.Log) < 2 || st.Log[0].Action != compliance.ActionBlocked || st.Log[0].Doc != "DA-26-1073" {
		t.Fatalf("compliance %+v", st)
	}

	// Removing the upstream lifts its block.
	if w := do(t, srv, http.MethodDelete, "/v1/upstreams/"+jsonID(up.ID), nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	rules, _ := db.Rules(context.Background())
	for _, r := range rules {
		if r.Origin == compliance.RuleOrigin {
			t.Fatalf("rule left after delete: %+v", r)
		}
	}
	if got := screen(); got == "reject" {
		t.Fatal("the call is still rejected after the upstream was removed")
	}
}

func TestUpstreamsWorkWithoutTheAutopilot(t *testing.T) {
	srv, _ := newTestServer(t)
	w := do(t, srv, http.MethodPost, "/v1/upstreams", map[string]any{"name": "Northwind", "ips": []string{"198.51.100.7"}})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	w = do(t, srv, http.MethodGet, "/v1/upstreams", nil)
	var res struct {
		Data []upstreamView `json:"data"`
		FCC  struct {
			Enabled bool `json:"enabled"`
		} `json:"fcc"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if len(res.Data) != 1 || res.Data[0].Check != nil || res.FCC.Enabled {
		t.Fatalf("list %+v", res)
	}
}

func jsonID(id int64) string {
	b, _ := json.Marshal(id)
	return string(b)
}
