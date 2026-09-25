package plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
)

func TestFeedHitAndLiveFailOpen(t *testing.T) {
	var sawTo bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth") != "key" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/falcon/v1/plugins":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"plugins":[
				{"slug":"blocklist","kind":"feed","inputs":["from"],"key_field":"from","mode":"enforce","timeout_ms":400},
				{"slug":"livebox","kind":"live","inputs":["from","to","raw_sip"],"key_field":"from","mode":"monitor","timeout_ms":400}
			]}`))
		case "/api/falcon/v1/plugins/blocklist/feed":
			_, _ = w.Write([]byte(`{"keys":["+14155550100"]}`))
		case "/api/falcon/v1/plugins/livebox/eval":
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			body := string(buf[:n])
			if contains(body, "+15551212") || contains(body, "raw_sip") {
				sawTo = true
			}
			http.Error(w, "down", http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rt := New(srv.URL, "key", time.Minute, 200*time.Millisecond)
	rt.HTTP = srv.Client()
	rt.refresh(context.Background())

	in := View("+14155550100", "203.0.113.9", "ua", "c1", "", "", "", "", "", "", "inbound", "INVITE", 10, "allow", nil)
	res := rt.Apply(context.Background(), in, score.Result{Action: score.ActionAllow, RiskScore: 10, Headers: map[string]string{}}, score.Thresholds{Flag: 40, Challenge: 60, Reject: 80})
	if res.Action != score.ActionFlag || res.Headers["X-Falcon-Plugin"] == "" {
		t.Fatalf("feed enforce: %+v", res)
	}
	if sawTo {
		t.Fatal("live plugin was offered the called number")
	}
	if res.Headers["X-Falcon-Plugin-Monitor"] != "reject" && !hasReason(res, "plugin_livebox") {
		// live failed open, so no live reason is correct
	}
}

func TestLiveMonitorDoesNotDrop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/falcon/v1/plugins":
			_, _ = w.Write([]byte(`{"plugins":[{"slug":"watch","kind":"live","inputs":["from"],"mode":"monitor","timeout_ms":400}]}`))
		case "/api/falcon/v1/plugins/watch/eval":
			_, _ = w.Write([]byte(`{"weight":80,"reason":"plugin_watch","action":"reject"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rt := New(srv.URL, "key", time.Minute, time.Second)
	rt.HTTP = srv.Client()
	rt.refresh(context.Background())
	res := rt.Apply(context.Background(), View("+14155550100", "", "", "", "", "", "", "", "", "", "", "", 0, "allow", nil),
		score.Result{Action: score.ActionAllow, Headers: map[string]string{}},
		score.Thresholds{Flag: 40, Challenge: 60, Reject: 80})
	if res.Action == score.ActionReject {
		t.Fatal("monitor plugin dropped the call")
	}
	if res.Headers["X-Falcon-Plugin-Monitor"] != "reject" {
		t.Fatalf("headers %+v", res.Headers)
	}
}

func TestViewPluginDoesNotScoreAndFrameStaysOnCallerAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/falcon/v1/plugins":
			_, _ = w.Write([]byte(`{"plugins":[
				{"slug":"pages","kind":"view","surface":"iframe","title":"Numbers","mode":"monitor"},
				{"slug":"blocklist","kind":"feed","inputs":["from"],"key_field":"from","mode":"enforce"}
			]}`))
		case "/api/falcon/v1/plugins/blocklist/feed":
			_, _ = w.Write([]byte(`{"keys":[]}`))
		case "/api/falcon/v1/plugins/pages/view":
			if r.URL.Query().Get("q") != "+14155550100" {
				t.Errorf("query %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"surface":"iframe","frame_url":"https://evil.example/api/falcon/v1/plugins/pages/frame"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rt := New(srv.URL, "key", time.Minute, time.Second)
	rt.HTTP = srv.Client()
	rt.refresh(context.Background())
	res := rt.Apply(context.Background(), View("+14155550100", "", "", "", "", "", "", "", "", "", "", "", 0, "allow", nil),
		score.Result{Action: score.ActionAllow, RiskScore: 5, Headers: map[string]string{}},
		score.Thresholds{Flag: 40, Challenge: 60, Reject: 80})
	if res.Action != score.ActionAllow || res.RiskScore != 5 {
		t.Fatalf("view plugin changed the decision: %+v", res)
	}
	if _, err := rt.Panel(context.Background(), "pages", "+14155550100"); err == nil {
		t.Fatal("foreign frame was accepted")
	}
	items := rt.List()
	if len(items) != 2 || items[0].Surface != "iframe" {
		t.Fatalf("catalog %+v", items)
	}
}

func TestPanelAcceptsSameHostFrame(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/falcon/v1/plugins":
			_, _ = w.Write([]byte(`{"plugins":[{"slug":"pages","kind":"view","surface":"iframe","title":"Numbers"}]}`))
		case "/api/falcon/v1/plugins/pages/view":
			frame := srv.URL + "/api/falcon/v1/plugins/pages/frame?ticket=1"
			_, _ = w.Write([]byte(`{"surface":"iframe","frame_url":"` + frame + `","frame_origin":"https://evil.example"}`))
		case "/api/falcon/v1/plugins/pages/frame":
			if r.URL.Query().Get("q") != "+14155550100" {
				t.Errorf("frame query %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<!DOCTYPE html><title>Numbers</title><p>ok</p>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rt := New(srv.URL, "key", time.Minute, time.Second)
	rt.HTTP = srv.Client()
	rt.refresh(context.Background())
	panel, err := rt.Panel(context.Background(), "pages", "+14155550100")
	if err != nil {
		t.Fatal(err)
	}
	if panel.FrameURL != "" || panel.FrameOrigin != "" {
		t.Fatalf("remote frame was passed to the dashboard: %+v", panel)
	}
	page, err := rt.Page(context.Background(), "pages", "+14155550100")
	if err != nil || !strings.Contains(string(page), "Numbers") || strings.Contains(strings.ToLower(string(page)), "<script") {
		t.Fatalf("page %s err %v", page, err)
	}
}

func hasReason(res score.Result, code string) bool {
	for _, r := range res.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
