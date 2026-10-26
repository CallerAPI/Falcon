package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

func seedCalls(t *testing.T, db *store.SQLite) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		_, _ = db.Insert(ctx, store.Event{ReceivedAt: now.Add(-time.Duration(i) * time.Minute), Action: score.ActionFlag, RiskScore: 50,
			From: "+13125550188", To: fmt.Sprintf("+1415555%04d", i), CallID: fmt.Sprintf("fan-%d", i), LatencyUS: int64(1000 + i*100),
			Reasons: []score.Reason{{Code: "caller_fanout", Weight: 25}}})
	}
	_, _ = db.Insert(ctx, store.Event{ReceivedAt: now, Action: score.ActionReject, RiskScore: 100, From: "+18005550199", To: "+14155550100",
		CallID: "spam-1", LatencyUS: 3000, Reasons: []score.Reason{{Code: "spam_feed_hit", Weight: 100}}})
	_, _ = db.Insert(ctx, store.Event{ReceivedAt: now, Action: score.ActionAllow, RiskScore: 5, From: "+12125550111", To: "+14155550100", CallID: "ok-1", LatencyUS: 900})
}

func TestOverviewHasNumbersLatencyAndActions(t *testing.T) {
	srv, db := newTestServer(t)
	seedCalls(t, db)
	w := do(t, srv, http.MethodGet, "/v1/overview?range=24h", nil)
	if w.Code != 200 {
		t.Fatalf("overview %d %s", w.Code, w.Body.String())
	}
	var ov Overview
	if err := json.Unmarshal(w.Body.Bytes(), &ov); err != nil {
		t.Fatal(err)
	}
	if ov.Totals.Screened != 32 || ov.Totals.Blocked != 1 || ov.Totals.Flagged != 30 || ov.Totals.Allowed != 1 {
		t.Fatalf("totals %+v", ov.Totals)
	}
	if ov.Latency.Count != 32 || ov.Latency.AvgMS <= 0 || ov.Latency.P95MS < ov.Latency.P50MS {
		t.Fatalf("latency %+v", ov.Latency)
	}
	// One row per caller: the dialer's 30 calls fold into one row.
	if len(ov.Recent) != 2 {
		t.Fatalf("recent %+v", ov.Recent)
	}
	for _, r := range ov.Recent {
		if r.Why == "" || r.Code == "" {
			t.Fatalf("recent row without a reason %+v", r)
		}
		if r.From == "+13125550188" && r.Calls != 30 {
			t.Fatalf("dialer calls %d", r.Calls)
		}
	}
	var block *Insight
	for i := range ov.Insights {
		switch ov.Insights[i].Key {
		case "number:+13125550188":
			block = &ov.Insights[i]
		case "number:+18005550199":
			t.Fatal("a number Falcon already blocks on every call is an insight")
		}
	}
	if block == nil || block.Action == nil || block.Action.Rule == nil || block.Action.Rule.Value != "+13125550188" {
		t.Fatalf("no block action for the fan-out number: %+v", ov.Insights)
	}

	// Blocking the number takes the insight away.
	if w := do(t, srv, http.MethodPost, "/v1/rules", block.Action.Rule); w.Code != http.StatusCreated {
		t.Fatalf("rule %d %s", w.Code, w.Body.String())
	}
	w = do(t, srv, http.MethodGet, "/v1/overview?range=24h", nil)
	_ = json.Unmarshal(w.Body.Bytes(), &ov)
	for _, in := range ov.Insights {
		if in.Key == "number:+13125550188" {
			t.Fatal("a blocked number is still an insight")
		}
	}
}

func TestOneInsightPerProposedRule(t *testing.T) {
	srv, db := newTestServer(t)
	seedCalls(t, db)
	if _, err := db.AddVoiceSample(context.Background(), store.VoiceSample{CallID: "fan-0", At: time.Now().UTC(), From: "+13125550188",
		Category: "Tax Collection", Score: 0.95}); err != nil {
		t.Fatal(err)
	}
	var ov Overview
	_ = json.Unmarshal(do(t, srv, http.MethodGet, "/v1/overview?range=24h", nil).Body.Bytes(), &ov)
	keys := map[string]bool{}
	for _, in := range ov.Insights {
		keys[in.Key] = true
	}
	if !keys["voice:+13125550188"] || keys["number:+13125550188"] {
		t.Fatalf("want the scam insight only: %v", keys)
	}
}

func TestFalseAnswersAreOneInsight(t *testing.T) {
	srv, db := newTestServer(t)
	srv.Cfg.FASMode = "monitor"
	ctx := context.Background()
	now := time.Now().UTC()
	for i, route := range []string{"Vendor X", "Vendor X", "Vendor Y"} {
		m := store.MediaCall{CallID: fmt.Sprintf("b-%d", i), Route: route, Carry: "route", StartedAt: now}
		id, err := db.InsertMediaCall(ctx, m)
		if err != nil {
			t.Fatal(err)
		}
		m.ID, m.AnswerMS, m.EndMS, m.Status, m.FAS, m.FASMS, m.FASAction = id, 2000, 9000, 200, "ringback", 4000, "observed"
		if err := db.UpdateMediaCall(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	var ov Overview
	_ = json.Unmarshal(do(t, srv, http.MethodGet, "/v1/overview?range=24h", nil).Body.Bytes(), &ov)
	var fas []Insight
	for _, in := range ov.Insights {
		if strings.HasPrefix(in.Key, "fas:") {
			fas = append(fas, in)
		}
	}
	if len(fas) != 1 || fas[0].Title != "3 false answers from 2 vendors" || !strings.HasPrefix(fas[0].Detail, "Vendor X 2, Vendor Y 1.") {
		t.Fatalf("fas insights %+v", fas)
	}
	if fas[0].Action == nil || fas[0].Action.Setting["fas_mode"] != "enforce" {
		t.Fatalf("no hold action %+v", fas[0].Action)
	}
}

func TestDismissHidesAnInsight(t *testing.T) {
	srv, db := newTestServer(t)
	seedCalls(t, db)
	if w := do(t, srv, http.MethodPost, "/v1/insights/dismiss", map[string]any{"key": "number:+13125550188", "hours": 1}); w.Code != 200 {
		t.Fatalf("dismiss %d", w.Code)
	}
	var ov Overview
	_ = json.Unmarshal(do(t, srv, http.MethodGet, "/v1/overview?range=24h", nil).Body.Bytes(), &ov)
	for _, in := range ov.Insights {
		if in.Key == "number:+13125550188" {
			t.Fatal("dismissed insight is back")
		}
	}
}

func TestMonitorModeOffersToStartBlocking(t *testing.T) {
	srv, db := newTestServer(t)
	srv.Cfg.Mode = "monitor"
	_, _ = db.Insert(context.Background(), store.Event{ReceivedAt: time.Now().UTC(), Action: score.ActionReject, Held: true, From: "+18005550199", CallID: "h1"})
	var ov Overview
	_ = json.Unmarshal(do(t, srv, http.MethodGet, "/v1/overview?range=24h", nil).Body.Bytes(), &ov)
	if ov.Totals.Held != 1 {
		t.Fatalf("held %d", ov.Totals.Held)
	}
	for _, in := range ov.Insights {
		if in.Key == "mode:monitor" && in.Action != nil && in.Action.Setting["mode"] == "enforce" {
			return
		}
	}
	t.Fatalf("no start blocking action: %+v", ov.Insights)
}

func TestEventFiltersByVerdictAndExplains(t *testing.T) {
	srv, db := newTestServer(t)
	seedCalls(t, db)
	var list struct {
		Data []store.Event `json:"data"`
	}
	_ = json.Unmarshal(do(t, srv, http.MethodGet, "/v1/events?range=24h&verdict=blocked", nil).Body.Bytes(), &list)
	if len(list.Data) != 1 || list.Data[0].CallID != "spam-1" {
		t.Fatalf("blocked filter %+v", list.Data)
	}
	var ev map[string]any
	_ = json.Unmarshal(do(t, srv, http.MethodGet, fmt.Sprintf("/v1/events/%d", list.Data[0].ID), nil).Body.Bytes(), &ev)
	why, _ := ev["why"].([]any)
	if len(why) == 0 || why[0].(map[string]any)["text"] != "The number is on the CallerAPI spam list." {
		t.Fatalf("why %+v", ev["why"])
	}
}

func TestRecordingIsServedWithRangeAndRefusesEscapes(t *testing.T) {
	srv, db := newTestServer(t)
	dir := t.TempDir()
	srv.Cfg.RecordingsDir = dir
	rel := filepath.Join("2026", "10", "20", "x.wav")
	_ = os.MkdirAll(filepath.Join(dir, "2026", "10", "20"), 0o750)
	_ = os.WriteFile(filepath.Join(dir, rel), []byte("RIFF....WAVEdata0123456789"), 0o640)
	id, _ := db.AddVoiceSample(context.Background(), store.VoiceSample{CallID: "c", AudioPath: rel, Channels: 2})
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/v1/recordings/%d.wav?token=secret", id), nil)
	req.Header.Set("Range", "bytes=0-3")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusPartialContent || w.Body.String() != "RIFF" || w.Header().Get("Content-Type") != "audio/wav" {
		t.Fatalf("range %d %q %s", w.Code, w.Body.String(), w.Header().Get("Content-Type"))
	}
	bad, _ := db.AddVoiceSample(context.Background(), store.VoiceSample{CallID: "d", AudioPath: "../../etc/passwd"})
	if w := do(t, srv, http.MethodGet, fmt.Sprintf("/v1/recordings/%d.wav", bad), nil); w.Code != http.StatusNotFound {
		t.Fatalf("escape served %d", w.Code)
	}
}

func TestRoutesSaveAndValidate(t *testing.T) {
	srv, _ := newTestServer(t)
	if w := do(t, srv, http.MethodPost, "/v1/routes", map[string]any{"prefix": "9901#", "label": "Vendor X", "carry": "all"}); w.Code != 200 {
		t.Fatalf("save %d %s", w.Code, w.Body.String())
	}
	for _, bad := range []map[string]any{{"prefix": "abc", "label": "x"}, {"prefix": "99", "label": ""}, {"prefix": "98", "label": "y", "target": "nohost"}, {"prefix": "97", "label": "z", "carry": "some"}} {
		if w := do(t, srv, http.MethodPost, "/v1/routes", bad); w.Code != http.StatusBadRequest {
			t.Fatalf("%v accepted: %d", bad, w.Code)
		}
	}
	var list struct {
		Data []store.Route `json:"data"`
	}
	_ = json.Unmarshal(do(t, srv, http.MethodGet, "/v1/routes", nil).Body.Bytes(), &list)
	if len(list.Data) != 1 || list.Data[0].Label != "Vendor X" {
		t.Fatalf("routes %+v", list.Data)
	}
	if w := do(t, srv, http.MethodDelete, fmt.Sprintf("/v1/routes/%d", list.Data[0].ID), nil); w.Code != 200 {
		t.Fatalf("delete %d", w.Code)
	}
}

func TestModulesListTheBuiltIns(t *testing.T) {
	srv, _ := newTestServer(t)
	var out struct {
		Data []Module `json:"data"`
	}
	_ = json.Unmarshal(do(t, srv, http.MethodGet, "/v1/modules", nil).Body.Bytes(), &out)
	ids := map[string]string{}
	for _, m := range out.Data {
		ids[m.ID] = m.State
	}
	for _, id := range []string{"shaken", "spam_list", "live_reputation", "ip_intel", "bcid", "network", "bridge", "fas", "voice_ai", "number_check"} {
		if _, ok := ids[id]; !ok {
			t.Fatalf("module %s missing: %v", id, ids)
		}
	}
	if ids["spam_list"] != "needs_key" || ids["number_check"] != "needs_key" {
		t.Fatalf("paid modules without a key: %v", ids)
	}
	if w := do(t, srv, http.MethodGet, "/v1/numbercheck/view", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("number check without a key: %d", w.Code)
	}
}

func TestDisplayTextSaysAbuseNotFraud(t *testing.T) {
	srv, _ := newTestServer(t)
	var out struct {
		Data []Module `json:"data"`
	}
	_ = json.Unmarshal(do(t, srv, http.MethodGet, "/v1/modules", nil).Body.Bytes(), &out)
	title := ""
	for _, m := range out.Data {
		if m.ID == "ip_intel" {
			title = m.Title
		}
		for _, text := range []string{m.Title, m.Summary, m.Detail, m.Enable} {
			if strings.Contains(strings.ToLower(text), "fraud") {
				t.Errorf("module %s: %q", m.ID, text)
			}
		}
	}
	if title != "Telecom IP abuse list" {
		t.Errorf("ip_intel title = %q", title)
	}
	for code, text := range plainReasons {
		if strings.Contains(strings.ToLower(text), "fraud") {
			t.Errorf("reason %s: %q", code, text)
		}
	}
	err := fs.WalkDir(WebFS(), "web", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !(strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".html") || strings.HasSuffix(name, ".css")) {
			return err
		}
		b, err := fs.ReadFile(WebFS(), name)
		if err != nil {
			return err
		}
		for n, line := range strings.Split(strings.ToLower(string(b)), "\n") {
			if i := strings.Index(line, "fraud"); i >= 0 {
				t.Errorf("%s:%d: %q", name, n+1, line[max(0, i-40):min(len(line), i+45)])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
