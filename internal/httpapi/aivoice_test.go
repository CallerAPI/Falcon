package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAIVoiceSettings(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.ai.live = false
	bad := do(t, srv, http.MethodPut, "/v1/plugins/ai-voice", map[string]any{"script_id": "not-a-number", "token": "secret-token"})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("bad id %d %s", bad.Code, bad.Body.String())
	}
	saved := do(t, srv, http.MethodPut, "/v1/plugins/ai-voice", map[string]any{"script_id": "10141", "token": "secret-token"})
	if saved.Code != http.StatusOK {
		t.Fatalf("save %d %s", saved.Code, saved.Body.String())
	}
	if strings.Contains(saved.Body.String(), "secret-token") {
		t.Fatal("token returned")
	}
	var body struct {
		ScriptID string `json:"script_id"`
		TokenSet bool   `json:"token_set"`
	}
	if err := json.Unmarshal(saved.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ScriptID != "10141" || !body.TokenSet {
		t.Fatalf("%+v", body)
	}
	got := do(t, srv, http.MethodGet, "/v1/plugins/ai-voice", nil)
	if got.Code != http.StatusOK || strings.Contains(got.Body.String(), "secret-token") {
		t.Fatalf("get %d %s", got.Code, got.Body.String())
	}
	list := do(t, srv, http.MethodGet, "/v1/plugins", nil)
	if !strings.Contains(list.Body.String(), "ai-voice") {
		t.Fatalf("list %s", list.Body.String())
	}
}
