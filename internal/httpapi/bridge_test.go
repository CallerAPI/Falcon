package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/plugin"
)

func TestBridgeSettingsStayOnHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"plugins":[{"slug":"ai-voice","title":"AI voice firewall","kind":"bridge","summary":"Scores transcripts.","bridge":{"transport":"websocket","url":"wss://app.connexcs.com/api/cp/scriptforge/{script_id}","headers":{"Authorization":"Bearer {token}"},"sink":"voice.transcript","settings":[{"key":"script_id","label":"Script id","pattern":"^[0-9]{1,12}$"},{"key":"token","label":"Access token","secret":true}]}}]}`))
	}))
	defer upstream.Close()
	rt := plugin.New(upstream.URL, "key", time.Minute, time.Millisecond)
	rt.HTTP = upstream.Client()
	rt.Load(context.Background())
	srv, _ := newTestServer(t)
	srv.Plugins = rt
	srv.bridges.live = false

	missing := do(t, srv, http.MethodPut, "/v1/plugins/other/settings", map[string]any{"values": map[string]string{}})
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing %d", missing.Code)
	}
	bad := do(t, srv, http.MethodPut, "/v1/plugins/ai-voice/settings", map[string]any{"values": map[string]string{"script_id": "nope", "token": "opaque-token"}})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("bad %d %s", bad.Code, bad.Body.String())
	}
	saved := do(t, srv, http.MethodPut, "/v1/plugins/ai-voice/settings", map[string]any{"values": map[string]string{"script_id": "10141", "token": "opaque-token"}})
	if saved.Code != http.StatusOK || strings.Contains(saved.Body.String(), "opaque-token") {
		t.Fatalf("save %d %s", saved.Code, saved.Body.String())
	}
	if !strings.Contains(saved.Body.String(), `"set":true`) {
		t.Fatalf("secret flag %s", saved.Body.String())
	}
}
