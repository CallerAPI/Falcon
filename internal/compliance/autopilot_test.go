package compliance

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/store"
)

type autopilotRig struct {
	db     *store.SQLite
	a      *Autopilot
	mode   string
	fired  []alerts.Fired
	reload int
}

func newRig(t *testing.T) *autopilotRig {
	t.Helper()
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "fcc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rig := &autopilotRig{db: db, mode: ModeMonitor}
	rig.a = &Autopilot{
		Store:  db,
		Mode:   func(context.Context) string { return rig.mode },
		Reload: func(context.Context) error { rig.reload++; return nil },
		Alert:  func(_ context.Context, f alerts.Fired) { rig.fired = append(rig.fired, f) },
		Now:    func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) },
	}
	return rig
}

func (r *autopilotRig) put(t *testing.T, u store.Upstream) store.Upstream {
	t.Helper()
	u, err := NormalizeUpstream(u)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := r.db.PutUpstream(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func (r *autopilotRig) fccRules(t *testing.T) []lists.Rule {
	t.Helper()
	all, err := r.db.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []lists.Rule
	for _, x := range all {
		if x.Origin == RuleOrigin {
			out = append(out, x)
		}
	}
	return out
}

func (r *autopilotRig) actions(t *testing.T) map[string]int {
	t.Helper()
	log, err := r.db.ComplianceLog(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, e := range log {
		out[e.Action+":"+e.Upstream]++
	}
	return out
}

func TestAutopilotMonitorAlertsAndBlocksNothing(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()
	rig.put(t, store.Upstream{Name: "Graystone", RMD: "RMD0000002", IPs: []string{"192.0.2.0/24"}, SPCs: []string{"123J"}})
	rig.put(t, store.Upstream{Name: "Northwind", RMD: "RMD0000001", IPs: []string{"198.51.100.10"}})
	rig.put(t, store.Upstream{Name: "Harbor Connect"})
	rig.a.Apply(testList())
	if err := rig.a.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(rig.fccRules(t)); n != 0 {
		t.Fatalf("monitor mode added %d rules", n)
	}
	if len(rig.fired) != 2 || rig.fired[0].Severity != "critical" || rig.fired[1].Severity != "warning" {
		t.Fatalf("alerts %+v", rig.fired)
	}
	acts := rig.actions(t)
	if acts["standing:Graystone"] != 1 || acts["standing:Northwind"] != 1 || acts["standing:Harbor Connect"] != 1 {
		t.Fatalf("log %v", acts)
	}
	ups, _ := rig.db.Upstreams(ctx)
	for _, u := range ups {
		if u.Standing == "" || u.StandingSince == nil {
			t.Fatalf("standing not saved: %+v", u)
		}
	}
	// A second pass with nothing new logs nothing and alerts nothing.
	if err := rig.a.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rig.fired) != 2 || len(rig.actions(t)) != 3 {
		t.Fatalf("second pass repeated itself: %d alerts, log %v", len(rig.fired), rig.actions(t))
	}
}

func TestAutopilotEnforceBlocksConfirmedUpstreamsOnly(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()
	gray := rig.put(t, store.Upstream{Name: "Graystone", RMD: "RMD0000002", IPs: []string{"192.0.2.0/24"}, SPCs: []string{"123J"}})
	rig.put(t, store.Upstream{Name: "Harbor Connect", IPs: []string{"203.0.113.0/24"}})
	if _, err := rig.db.AddRule(ctx, lists.Rule{Kind: lists.Deny, Subject: lists.IP, Value: "203.0.113.9", Note: "the operator's own"}); err != nil {
		t.Fatal(err)
	}
	rig.a.Apply(testList())
	rig.mode = ModeEnforce
	if err := rig.a.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	rules := rig.fccRules(t)
	if len(rules) != 2 {
		t.Fatalf("want the address and the signer of the confirmed upstream, got %+v", rules)
	}
	for _, r := range rules {
		if r.Kind != lists.Deny || (r.Value != "192.0.2.0/24" && r.Value != "123J") {
			t.Fatalf("rule %+v", r)
		}
	}
	if rig.reload == 0 {
		t.Fatal("rules changed and the index was not rebuilt")
	}
	if acts := rig.actions(t); acts["blocked:Graystone"] != 1 || acts["blocked:Harbor Connect"] != 0 {
		t.Fatalf("log %v", acts)
	}
	if err := rig.a.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if acts := rig.actions(t); acts["blocked:Graystone"] != 1 {
		t.Fatalf("a second pass logged the block again: %v", acts)
	}
	if u, ok := rig.a.Owner("192.0.2.77", ""); !ok || u.ID != gray.ID {
		t.Fatalf("owner of 192.0.2.77: %+v %v", u, ok)
	}

	// The FCC lifts the order: the next list lists the provider again.
	l := testList()
	l.Providers[1].Order, l.Providers[1].OrderDoc, l.Providers[1].Listed = "", "", true
	rig.a.Apply(l)
	if err := rig.a.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(rig.fccRules(t)); n != 0 {
		t.Fatalf("%d rules left after the order was lifted", n)
	}
	if acts := rig.actions(t); acts["released:Graystone"] != 1 {
		t.Fatalf("log %v", acts)
	}
	all, _ := rig.db.Rules(ctx)
	if len(all) != 1 || all[0].Note != "the operator's own" {
		t.Fatalf("the operator's own rule must stay: %+v", all)
	}
}

func TestAutopilotMonitorReleasesBlocks(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()
	rig.put(t, store.Upstream{Name: "Graystone", RMD: "RMD0000002", IPs: []string{"192.0.2.0/24"}})
	rig.a.Apply(testList())
	rig.mode = ModeEnforce
	if err := rig.a.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	rig.mode = ModeMonitor
	if err := rig.a.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(rig.fccRules(t)); n != 0 {
		t.Fatalf("monitor mode kept %d rules", n)
	}
	log, _ := rig.db.ComplianceLog(ctx, 10)
	if log[0].Action != ActionReleased || log[0].Detail != "Deny rules removed. The autopilot is in monitor mode." {
		t.Fatalf("latest entry %+v", log[0])
	}
}

// A fetch failure on a fresh start must not lift a block that is in place.
func TestAutopilotKeepsBlocksWithoutAList(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()
	rig.put(t, store.Upstream{Name: "Graystone", RMD: "RMD0000002", IPs: []string{"192.0.2.0/24"}})
	rig.a.Apply(testList())
	rig.mode = ModeEnforce
	if err := rig.a.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	fresh := &Autopilot{Store: rig.db, Mode: rig.a.Mode}
	if err := fresh.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(rig.fccRules(t)); n != 1 {
		t.Fatalf("a pass with no list left %d rules, want 1", n)
	}
	// The saved list loads on the next start.
	fresh.loadSaved(ctx)
	if fresh.currentIndex() != nil {
		t.Fatal("Apply does not save the list. Only a fetch does.")
	}
}
