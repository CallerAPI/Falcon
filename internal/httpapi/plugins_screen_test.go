package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/plugin"
)

func TestScreenUsesCatalogAndKeepsCalledNumber(t *testing.T) {
	var sawCalled bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth") != "key" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/falcon/v1/plugins":
			_, _ = w.Write([]byte(`{"plugins":[
				{"slug":"blocklist","kind":"feed","inputs":["from"],"key_field":"from","mode":"enforce"},
				{"slug":"watch","kind":"live","inputs":["from","to","raw_sip"],"mode":"monitor"}
			]}`))
		case "/api/falcon/v1/plugins/blocklist/feed":
			_, _ = w.Write([]byte(`{"keys":["+14155550100"]}`))
		case "/api/falcon/v1/plugins/watch/eval":
			buf := make([]byte, 2048)
			n, _ := r.Body.Read(buf)
			if strings.Contains(string(buf[:n]), "+15551212") || strings.Contains(string(buf[:n]), "raw_sip") {
				sawCalled = true
			}
			http.Error(w, "down", http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	rt := plugin.New(upstream.URL, "key", time.Minute, 200*time.Millisecond)
	rt.HTTP = upstream.Client()
	rt.Load(context.Background())

	srv, _ := newTestServer(t)
	srv.Plugins = rt
	res := screen(t, srv, "198.51.100.20", cleanInvite("+14155550100", "Acme-SBC/1.0"))
	if res.Headers["X-Falcon-Plugin"] == "" || res.Headers["X-Falcon-Score"] != strconv.Itoa(res.RiskScore) {
		t.Fatalf("catalog did not apply: action %s score %d headers %v", res.Action, res.RiskScore, res.Headers)
	}
	status, _ := res.Action.SIP()
	if res.SIPStatus != status {
		t.Fatalf("sip status %d want %d for %s", res.SIPStatus, status, res.Action)
	}
	if sawCalled {
		t.Fatal("live plugin was offered the called number")
	}
}
