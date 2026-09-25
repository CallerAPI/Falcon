package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/fleet"
	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

func TestFleetMemberInheritsRulesEventsAndBehaviour(t *testing.T) {
	hubDB := openFleetDB(t)
	memberDB := openFleetDB(t)
	hub := &Server{
		Cfg:       config.Config{Token: "hub-admin", FleetHub: true, FleetToken: "fleet-secret", StoreRawSIP: true},
		Engine:    score.NewEngine(score.Thresholds{Flag: 40, Challenge: 60, Reject: 80}, score.Limits{Window: time.Minute}),
		Store:     hubDB,
		InstallID: "hub",
	}
	ts := httptest.NewServer(hub.Handler())
	defer ts.Close()

	if _, err := hubDB.AddRule(context.Background(), lists.Rule{Kind: lists.Deny, Subject: lists.Number, Value: "+14155550100", Note: "fleet"}); err != nil {
		t.Fatal(err)
	}
	if _, err := hubDB.Insert(context.Background(), store.Event{Action: score.ActionAllow, From: "+14155550100", To: "+15551111", CallID: "other", Switch: "sbc-2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := memberDB.AddRule(context.Background(), lists.Rule{Kind: lists.Allow, Subject: lists.SPC, Value: "9999", Note: "local"}); err != nil {
		t.Fatal(err)
	}
	if _, err := memberDB.Insert(context.Background(), store.Event{Action: score.ActionReject, From: "+14155550100", To: "+15552222", CallID: "local", Switch: "sbc-1", RawSIP: "INVITE sip:+15552222@x SIP/2.0\r\n\r\n"}); err != nil {
		t.Fatal(err)
	}

	cache := fleet.NewCache(time.Minute)
	member := &fleet.Member{
		URL: ts.URL, Token: "fleet-secret", InstallID: "sbc-1", Store: memberDB, Cache: cache,
		Reload: func(ctx context.Context) error { return nil },
	}
	member.Sync(context.Background())

	rules, err := memberDB.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var sawDeny, sawAllow bool
	for _, r := range rules {
		if r.Kind == lists.Deny && r.Origin == "fleet" {
			sawDeny = true
		}
		if r.Kind == lists.Allow && r.Origin == "local" {
			sawAllow = true
		}
	}
	if !sawDeny || !sawAllow {
		t.Fatalf("rules %+v", rules)
	}

	events, err := hubDB.Recent(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var copied bool
	for _, ev := range events {
		if ev.CallID != "local" || ev.Peer != "sbc-1" {
			continue
		}
		full, err := hubDB.Get(context.Background(), ev.ID)
		if err != nil {
			t.Fatal(err)
		}
		if full.RawSIP != "" {
			copied = true
		}
	}
	if !copied {
		t.Fatalf("hub events %+v", events)
	}

	merged := cache.Merge("+14155550100", store.Activity{Calls: 1, DistinctCallees: 1})
	if merged.Calls < 2 {
		t.Fatalf("behaviour %+v", merged)
	}

	pending, err := memberDB.FleetPending(context.Background(), 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending %+v %v", pending, err)
	}

	spareDB := openFleetDB(t)
	spare := &fleet.Member{
		URL: ts.URL, Token: "fleet-secret", InstallID: "spare", Store: spareDB, Cache: fleet.NewCache(time.Minute),
		Reload: hub.ReloadRules,
	}
	spare.Sync(context.Background())
	spareRules, err := spareDB.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(spareRules) != 1 || spareRules[0].Origin != "fleet" || spareRules[0].Kind != lists.Deny {
		t.Fatalf("spare rules %+v", spareRules)
	}
}

func TestFleetPushFailureKeepsTheEvent(t *testing.T) {
	memberDB := openFleetDB(t)
	if _, err := memberDB.Insert(context.Background(), store.Event{Action: score.ActionReject, From: "+14155550100", CallID: "keep"}); err != nil {
		t.Fatal(err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer bad.Close()
	member := &fleet.Member{URL: bad.URL, Token: "wrong", InstallID: "sbc-1", Store: memberDB}
	member.Sync(context.Background())
	pending, err := memberDB.FleetPending(context.Background(), 10)
	if err != nil || len(pending) != 1 || pending[0].CallID != "keep" {
		t.Fatalf("pending after reject %+v %v", pending, err)
	}

	down := &fleet.Member{URL: "http://127.0.0.1:1", Token: "fleet-secret", InstallID: "sbc-1", Store: memberDB, HTTP: &http.Client{Timeout: 200 * time.Millisecond}}
	down.Sync(context.Background())
	pending, err = memberDB.FleetPending(context.Background(), 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending after outage %+v %v", pending, err)
	}
}

func TestFleetHubRejectsABadTokenAndALargeBatch(t *testing.T) {
	hubDB := openFleetDB(t)
	hub := &Server{
		Cfg:    config.Config{FleetHub: true, FleetToken: "fleet-secret"},
		Store:  hubDB,
		Engine: score.NewEngine(score.Thresholds{}, score.Limits{}),
	}
	ts := httptest.NewServer(hub.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/fleet/events", strings.NewReader(`{"install_id":"sbc-1","events":[]}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}

	events := make([]store.Event, 51)
	body, _ := json.Marshal(map[string]any{"install_id": "sbc-1", "events": events})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/v1/fleet/events", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer fleet-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("batch status %d", resp.StatusCode)
	}
}

func openFleetDB(t *testing.T) *store.SQLite {
	t.Helper()
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
