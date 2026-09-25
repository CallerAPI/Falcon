package plugin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/sdk"
)

func TestNewDefaultsAndNilRuntime(t *testing.T) {
	rt := New("https://api.example/", "", 0, 0)
	if rt.Refresh != time.Minute || rt.Budget != 400*time.Millisecond || rt.BaseURL != "https://api.example" {
		t.Fatalf("defaults %+v", rt)
	}
	if rt.Enabled() || New("https://api.example", "key", time.Second, time.Second).Enabled() != true {
		t.Fatal("enabled")
	}
	var none *Runtime
	if none.Enabled() || none.Count() != 0 || none.List() != nil {
		t.Fatal("nil runtime")
	}
	res := none.Apply(context.Background(), sdk.Input{}, score.Result{Action: score.ActionAllow}, score.Thresholds{})
	if res.Action != score.ActionAllow {
		t.Fatal("nil apply")
	}
	if _, err := none.Panel(context.Background(), "a", ""); err == nil {
		t.Fatal("nil panel")
	}
	if _, err := none.Page(context.Background(), "a", ""); err == nil {
		t.Fatal("nil page")
	}
	none.Run(context.Background())
}

func TestRunStopsWhenContextEnds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"plugins":[]}`))
	}))
	defer srv.Close()
	rt := New(srv.URL, "key", 20*time.Millisecond, time.Millisecond)
	rt.HTTP = srv.Client()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rt.Run(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("run did not return")
	}
	if rt.Count() != 0 {
		t.Fatal("count")
	}
}

func TestRefreshKeepsCatalogWhenUpstreamFails(t *testing.T) {
	rt := New("http://127.0.0.1:1", "key", time.Minute, time.Millisecond)
	rt.Load(context.Background())
	if rt.Count() != 0 {
		t.Fatal("dial failure replaced the catalog")
	}
	rt.BaseURL = ":// bad"
	rt.refresh(context.Background())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/falcon/v1/plugins":
			http.Error(w, "no", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rt = New(srv.URL, "key", time.Minute, time.Millisecond)
	rt.HTTP = srv.Client()
	rt.Load(context.Background())
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{`))
	})
	rt.Load(context.Background())
	if rt.Count() != 0 {
		t.Fatal("bad catalog stored")
	}
}

func TestFeedMissSourceIPAndLiveClamp(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/falcon/v1/plugins":
			_, _ = w.Write([]byte(`{"plugins":[
				{"slug":"ips","kind":"feed","key_field":"source_ip","mode":"enforce"},
				{"slug":"odd","kind":"other"},
				{"slug":"live","kind":"live","inputs":["from"],"mode":"enforce"}
			]}`))
		case "/api/falcon/v1/plugins/ips/feed":
			_, _ = w.Write([]byte(`{"keys":["203.0.113.9"]}`))
		case "/api/falcon/v1/plugins/live/eval":
			calls++
			_, _ = w.Write([]byte(`{"weight":500,"action":"reject","detail":"` + strings.Repeat("d", 200) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rt := New(srv.URL, "key", time.Minute, time.Second)
	rt.HTTP = srv.Client()
	rt.Load(context.Background())
	miss := rt.Apply(context.Background(), sdk.Input{SourceIP: "198.51.100.1"}, score.Result{Action: score.ActionAllow, Headers: map[string]string{}}, score.Thresholds{Flag: 40, Challenge: 60, Reject: 80})
	if miss.Action != score.ActionReject || miss.Headers["X-Falcon-Block"] != "plugin" || miss.RiskScore != 100 {
		t.Fatalf("live clamp %+v", miss)
	}
	if calls != 1 || len(miss.Reasons) == 0 || len(miss.Reasons[0].Detail) > 120 || miss.Reasons[0].Code != "plugin_live" {
		t.Fatalf("reason %+v calls %d", miss.Reasons, calls)
	}
	hit := rt.Apply(context.Background(), sdk.Input{SourceIP: "203.0.113.9"}, score.Result{Action: score.ActionReject, RiskScore: 90, Headers: map[string]string{"X-Falcon-Block": "denylist"}}, score.Thresholds{})
	if hit.Action != score.ActionReject || hit.RiskScore != 100 {
		t.Fatalf("feed on reject %+v", hit)
	}
}

func TestMonitorChallengeAndEmptyCatalog(t *testing.T) {
	rt := &Runtime{items: []sdk.Manifest{{Slug: "w", Kind: "live", Mode: "monitor", Inputs: []string{"from"}}}, feeds: map[string]map[string]struct{}{}}
	rt.BaseURL = "http://127.0.0.1"
	rt.APIKey = "key"
	rt.Budget = time.Millisecond
	rt.HTTP = &http.Client{Timeout: time.Millisecond}
	res := rt.Apply(context.Background(), sdk.Input{}, score.Result{Action: score.ActionAllow}, score.Thresholds{Flag: 40, Challenge: 60, Reject: 80})
	if res.Action != score.ActionAllow {
		t.Fatalf("failed live changed %+v", res)
	}
	out, ok := feedHit(sdk.Manifest{Slug: "empty"}, sdk.Input{From: "+1"}, nil)
	if ok || out.Weight != 0 {
		t.Fatal("empty feed hit")
	}
	res = patch(score.Result{Action: score.ActionAllow}, sdk.Manifest{Slug: "m", Mode: "monitor"}, sdk.Output{Weight: -3, Action: "challenge"}, score.Thresholds{Flag: 1, Challenge: 1, Reject: 1})
	if res.Action != score.ActionFlag || res.Headers["X-Falcon-Plugin-Monitor"] != "challenge" {
		t.Fatalf("monitor %+v", res)
	}
	res = patch(score.Result{Action: score.ActionAllow, Headers: map[string]string{}}, sdk.Manifest{Slug: "s"}, sdk.Output{Weight: 10}, score.Thresholds{Flag: 1, Challenge: 50, Reject: 80})
	if res.Headers["X-Falcon-Score"] != "10" {
		t.Fatalf("threshold %+v", res)
	}
}

func TestPanelAndPageErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/falcon/v1/plugins":
			_, _ = w.Write([]byte(`{"plugins":[
				{"slug":"badfeed","kind":"feed"},
				{"slug":"page","kind":"view","surface":"iframe","title":"Page"},
				{"slug":"native","kind":"view","surface":"native","title":"Native"}
			]}`))
		case "/api/falcon/v1/plugins/badfeed/feed":
			http.Error(w, "no", http.StatusBadGateway)
		case "/api/falcon/v1/plugins/page/view":
			if strings.Contains(r.URL.RawQuery, "%3C") {
				t.Errorf("markup query forwarded: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"surface":"iframe","widget":"table","columns":[{"key":"status","label":"Status"}]}`))
		case "/api/falcon/v1/plugins/page/frame":
			if r.URL.Query().Get("script") == "1" {
				_, _ = w.Write([]byte(`<html><script>alert(1)</script></html>`))
				return
			}
			_, _ = w.Write([]byte(`<!DOCTYPE html><p>Page</p>`))
		case "/api/falcon/v1/plugins/native/view":
			http.Error(w, "{", http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rt := New(srv.URL, "key", time.Minute, time.Millisecond)
	rt.HTTP = srv.Client()
	rt.Load(context.Background())
	if rt.Count() != 3 {
		t.Fatalf("count %d", rt.Count())
	}
	if _, err := rt.Panel(context.Background(), "missing", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	panel, err := rt.Panel(context.Background(), "page", "a<b>")
	if err != nil || panel.FrameURL != "" || panel.Title != "Page" {
		t.Fatalf("panel %+v %v", panel, err)
	}
	page, err := rt.Page(context.Background(), "page", "+1")
	if err != nil || !strings.Contains(string(page), "Page") {
		t.Fatal(err)
	}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<script>x</script>`))
	})
	if _, err := rt.Page(context.Background(), "page", ""); err == nil {
		t.Fatal("script page accepted")
	}
	if _, err := rt.Panel(context.Background(), "native", ""); err == nil {
		t.Fatal("bad json accepted")
	}
	if _, err := rt.Page(context.Background(), "native", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	empty := &Runtime{APIKey: "key"}
	if got := empty.Apply(context.Background(), sdk.Input{}, score.Result{Action: score.ActionAllow}, score.Thresholds{}); got.Action != score.ActionAllow {
		t.Fatal("empty catalog")
	}
	in := View("+1", "ip", "ua", "id", "A", "pass", "spc", "name", "prov", "fp", "in", "INVITE", 3, "allow", []score.Reason{{}, {Code: "missing_identity"}})
	if in.ReasonCodes != "missing_identity" || in.Score != "3" {
		t.Fatalf("view %+v", in)
	}
	bare := syncDecision(score.Result{Action: score.ActionFlag, RiskScore: 4})
	if bare.Headers["X-Falcon-Score"] != "4" {
		t.Fatal("nil headers")
	}
	raised := patch(score.Result{Action: score.ActionAllow, Headers: map[string]string{}}, sdk.Manifest{Slug: "c", Mode: "enforce"}, sdk.Output{Action: "challenge"}, score.Thresholds{})
	if raised.Action != score.ActionChallenge {
		t.Fatalf("challenge %+v", raised)
	}
	broken := &Runtime{
		BaseURL: "http://[", APIKey: "k", Budget: time.Millisecond,
		items: []sdk.Manifest{{Slug: "p", Kind: "view", Surface: "native"}, {Slug: "f", Kind: "view", Surface: "iframe"}, {Slug: "bad\n", Kind: "live", Inputs: []string{"from"}}},
	}
	if _, err := broken.Panel(context.Background(), "p", "q"); err == nil {
		t.Fatal("bad panel url")
	}
	if _, err := broken.Page(context.Background(), "f", "q"); err == nil {
		t.Fatal("bad page url")
	}
	if _, err := broken.evalLive(context.Background(), sdk.Manifest{Slug: "bad\n"}, sdk.Input{From: "+1"}); err == nil {
		t.Fatal("bad eval url")
	}
	broken.BaseURL = srv.URL
	broken.HTTP = nil
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/eval") {
			_, _ = w.Write([]byte(`{`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/view") {
			http.Error(w, "no", http.StatusBadGateway)
			return
		}
		http.Error(w, "no", http.StatusBadGateway)
	})
	if _, err := broken.evalLive(context.Background(), sdk.Manifest{Slug: "live", Inputs: []string{"from"}}, sdk.Input{From: "+1"}); err == nil {
		t.Fatal("bad eval json")
	}
	if _, err := broken.Panel(context.Background(), "p", ""); err == nil {
		t.Fatal("panel status")
	}
	if _, err := broken.Page(context.Background(), "f", ""); err == nil {
		t.Fatal("page status")
	}
	down := &Runtime{BaseURL: srv.URL, APIKey: "k", items: broken.items, HTTP: &http.Client{Transport: failTransport{}}}
	if _, err := down.Panel(context.Background(), "p", ""); err == nil {
		t.Fatal("panel dial")
	}
	if _, err := down.pullFeed(context.Background(), "ips"); err == nil {
		t.Fatal("feed dial")
	}
	if _, err := down.Page(context.Background(), "f", ""); err == nil {
		t.Fatal("page dial")
	}
	readErr := &Runtime{BaseURL: srv.URL, APIKey: "k", items: broken.items, HTTP: &http.Client{Transport: bodyTransport{}}}
	if _, err := readErr.Page(context.Background(), "f", ""); err == nil {
		t.Fatal("page read")
	}
	if _, err := (&Runtime{BaseURL: "http://[", APIKey: "k"}).pullFeed(context.Background(), "ips"); err == nil {
		t.Fatal("feed url")
	}
	jsonSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{`))
	}))
	defer jsonSrv.Close()
	if _, err := (&Runtime{BaseURL: jsonSrv.URL, APIKey: "k", HTTP: jsonSrv.Client()}).pullFeed(context.Background(), "ips"); err == nil {
		t.Fatal("feed json")
	}
}

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("down")
}

type bodyTransport struct{}

func (bodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: errReadCloser{}, Header: make(http.Header)}, nil
}

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("read") }
func (errReadCloser) Close() error             { return nil }
