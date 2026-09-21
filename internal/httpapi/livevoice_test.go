package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
)

func signedPost(t *testing.T, srv *Server, key string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/voice/verdict", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Voice-Event", body["type"].(string))
	if key != "" {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write(b)
		req.Header.Set("X-Voice-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestLiveVerdictFlow(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.Cfg.CallerAPIKey = "acct-key"
	hooks := withHook(t, srv)

	// The INVITE Falcon screened for this call, an outbound call from a
	// known customer.
	res := screenJSON(t, srv, map[string]any{
		"switch": "connexcs", "direction": "outbound", "customer": "acme", "method": "INVITE",
		"request_uri": "sip:+14155550100@connexcs.invalid", "source_ip": "203.0.113.9",
		"headers": map[string]string{"From": "<sip:+13125550199@203.0.113.9>;tag=1", "To": "<sip:+14155550100@x>", "Call-ID": "live-1", "User-Agent": "dialer"},
	})
	if res.Action != score.ActionAllow {
		t.Fatalf("setup: %v", res.Action)
	}

	// Bad signature and no token: refused.
	w := signedPost(t, srv, "wrong-key", map[string]any{"type": "session.started", "session_id": "s1", "call_id": "live-1", "from": "+13125550199"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature accepted: %d", w.Code)
	}

	w = signedPost(t, srv, "acct-key", map[string]any{"type": "session.started", "session_id": "s1", "call_id": "live-1", "from": "+13125550199", "at": time.Now()})
	if w.Code != http.StatusAccepted {
		t.Fatalf("started: %d %s", w.Code, w.Body.String())
	}
	// A weak rules-only verdict: recorded, no page.
	w = signedPost(t, srv, "acct-key", map[string]any{"type": "verdict", "session_id": "s1", "call_id": "live-1",
		"verdict": map[string]any{"score": 0.55, "level": "medium", "category": "Bank/Credit Card Company Imposter", "signals": []string{"mentions account suspension"}, "source": "heuristic"}})
	if w.Code != http.StatusAccepted {
		t.Fatalf("verdict1: %d %s", w.Code, w.Body.String())
	}
	if hooks.len() != 0 {
		t.Fatalf("weak verdict must not page")
	}
	// The model confirms: page, with the outbound action.
	w = signedPost(t, srv, "acct-key", map[string]any{"type": "verdict", "session_id": "s1", "call_id": "live-1",
		"verdict": map[string]any{"score": 0.91, "level": "high", "category": "Bank/Credit Card Company Imposter", "summary": "Caller claims to be the bank fraud desk and asks for the one time code.", "signals": []string{"asks for OTP"}, "tactics": []string{"urgency"}, "source": "combined"}})
	if w.Code != http.StatusAccepted {
		t.Fatalf("verdict2: %d %s", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for hooks.len() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	got := hooks.snapshot()
	if len(got) != 1 {
		t.Fatalf("pages = %d", len(got))
	}
	data := got[0]["falcon"].(map[string]any)["data"].(map[string]any)
	if data["kind"] != "voice_scam" || data["live"] != true || data["customer_id"] != "acme" || data["calling_number"] != "+13125550199" ||
		data["call_id"] != "live-1" || data["direction"] != "outbound" || data["suggested_action"] != "hangup_unassign_did_and_review_customer" {
		t.Fatalf("page data: %v", data)
	}
	// A later lower score does not erase the worst one. The transcript
	// lands with the end of the session.
	w = signedPost(t, srv, "acct-key", map[string]any{"type": "session.ended", "session_id": "s1", "call_id": "live-1", "duration_seconds": 47, "transcript": "caller: this is your bank ...",
		"verdict": map[string]any{"score": 0.8, "level": "high", "category": "Bank/Credit Card Company Imposter", "source": "combined"}})
	if w.Code != http.StatusAccepted {
		t.Fatalf("ended: %d %s", w.Code, w.Body.String())
	}

	list := do(t, srv, http.MethodGet, "/v1/voice/samples", nil)
	var out struct {
		Data []struct {
			CallID     string  `json:"call_id"`
			EventID    int64   `json:"event_id"`
			Provider   string  `json:"provider"`
			Score      float64 `json:"score"`
			Category   string  `json:"category"`
			Transcript string  `json:"transcript"`
			Seconds    float64 `json:"seconds"`
			Customer   string  `json:"customer"`
		} `json:"data"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Data) != 1 {
		t.Fatalf("one sample per session, got %d", len(out.Data))
	}
	s := out.Data[0]
	if s.CallID != "live-1" || s.EventID == 0 || s.Provider != LiveProvider || s.Score != 0.91 || s.Transcript == "" || s.Seconds != 47 || s.Customer != "acme" {
		t.Fatalf("sample: %+v", s)
	}
	// Same customer again within the hour: the page is deduplicated.
	screenJSON(t, srv, map[string]any{
		"switch": "connexcs", "direction": "outbound", "customer": "acme", "method": "INVITE",
		"request_uri": "sip:+14155550101@connexcs.invalid", "source_ip": "203.0.113.9",
		"headers": map[string]string{"From": "<sip:+13125550198@203.0.113.9>;tag=1", "To": "<sip:+14155550101@x>", "Call-ID": "live-2", "User-Agent": "dialer"},
	})
	w = signedPost(t, srv, "acct-key", map[string]any{"type": "verdict", "session_id": "s2", "call_id": "live-2", "from": "+13125550198",
		"verdict": map[string]any{"score": 0.95, "category": "Tax Collection", "source": "llm"}})
	if w.Code != http.StatusAccepted {
		t.Fatalf("verdict s2: %d", w.Code)
	}
	time.Sleep(100 * time.Millisecond)
	if hooks.len() != 1 {
		t.Fatalf("cooldown: pages = %d", hooks.len())
	}
}

func TestLiveVerdictAcceptsFalconTokenWithoutKey(t *testing.T) {
	srv, _ := newTestServer(t)
	b, _ := json.Marshal(map[string]any{"type": "verdict", "session_id": "s9", "call_id": "unknown-call", "from": "+13125550100",
		"verdict": map[string]any{"score": 0.2, "category": "Other", "source": "heuristic"}})
	req := httptest.NewRequest(http.MethodPost, "/v1/voice/verdict", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth must be refused: %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/voice/verdict", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Falcon-Token", "secret")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
}
