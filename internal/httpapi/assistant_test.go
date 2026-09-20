package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValueCardNeedsNoModel(t *testing.T) {
	srv, _ := newTestServer(t)
	_ = do(t, srv, http.MethodPut, "/v1/customers", map[string]any{"id": "acme", "dids": []string{"+1312555*"}})
	screenJSON(t, srv, outboundInvite("+13125550100", "+14155550100", "v-ok"))
	screenJSON(t, srv, outboundInvite("+18005551234", "+14155550100", "v-spoof"))
	_ = do(t, srv, http.MethodPost, "/v1/outcome", map[string]any{"call_id": "v-ok", "answered": true, "duration_s": 120})

	w := do(t, srv, http.MethodGet, "/v1/value?range=1h", nil)
	var v Value
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if v.Screened != 2 || v.Blocked != 1 || v.SpoofsStopped != 1 || v.Outbound != 2 || v.OutboundBlocked != 1 {
		t.Fatalf("value: %+v", v)
	}
	if v.MinutesNotCarried < 1.9 || v.MinutesNotCarried > 2.1 {
		t.Fatalf("minutes not carried = %v", v.MinutesNotCarried)
	}
	if !strings.Contains(v.Sentence, "blocked 1 (50.0%)") || !strings.Contains(v.Sentence, "stopped 1 spoofed caller id") {
		t.Fatalf("sentence: %s", v.Sentence)
	}

	// No provider: the assistant still answers with the value sentence.
	w = do(t, srv, http.MethodPost, "/v1/assistant", map[string]any{"question": "what happened?", "range": "1h"})
	var a struct {
		Answer   string `json:"answer"`
		Provider string `json:"provider"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &a)
	if w.Code != 200 || a.Provider != "none" || a.Answer != v.Sentence {
		t.Fatalf("assistant without provider: %d %s", w.Code, w.Body.String())
	}
}

func TestAssistantUsesOpenAICompatibleProviderWithContext(t *testing.T) {
	srv, _ := newTestServer(t)
	screenJSON(t, srv, outboundInvite("+13125550100", "+14155550100", "a-1"))
	var gotSystem, gotAuth string
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		var req struct {
			Model    string `json:"model"`
			Messages []struct{ Role, Content string }
		}
		_ = json.Unmarshal(b, &req)
		gotSystem = req.Messages[0].Content
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": "One call screened, none blocked."}}}})
	}))
	defer llm.Close()
	srv.Assistant = AssistantConfig{Provider: "openai", BaseURL: llm.URL, APIKey: "k", Model: "test-model"}

	w := do(t, srv, http.MethodPost, "/v1/assistant", map[string]any{"question": "summary?", "range": "1h", "history": []map[string]string{{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "One call screened") {
		t.Fatalf("assistant: %d %s", w.Code, w.Body.String())
	}
	if gotAuth != "Bearer k" || !strings.Contains(gotSystem, `"screened":1`) || !strings.Contains(gotSystem, "Never invent numbers") {
		t.Fatalf("provider request: auth=%q system=%.200s", gotAuth, gotSystem)
	}
}
