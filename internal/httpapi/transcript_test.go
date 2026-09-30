package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

func TestReadTranscript(t *testing.T) {
	line := readTranscript([]byte(`{"data":{"callid":"abc","cli":"+1512","dest_number":"+1915","transcript":"pay with gift cards","final":true}}`))
	if line.CallID != "abc" || line.From != "+1512" || line.To != "+1915" || line.Text != "pay with gift cards" || !line.Final {
		t.Fatalf("%+v", line)
	}
	plain := readTranscript([]byte(`not json`))
	if plain.Text != "not json" {
		t.Fatalf("%+v", plain)
	}
	empty := readTranscript([]byte(`{"status":"ok"}`))
	if empty.Text != "" || empty.Raw == "" {
		t.Fatalf("%+v", empty)
	}
}

func TestTranscriptAttachesByCallID(t *testing.T) {
	srv, _ := newTestServer(t)
	screenJSON(t, srv, map[string]any{
		"switch": "connexcs", "direction": "outbound", "method": "INVITE",
		"request_uri": "sip:+14155550100@connexcs.invalid", "source_ip": "203.0.113.9",
		"headers": map[string]string{
			"From": "<sip:+13125550199@203.0.113.9>;tag=1", "To": "<sip:+14155550100@x>",
			"Call-ID": "cx-call-9", "User-Agent": "dialer",
		},
	})
	w := do(t, srv, http.MethodPost, "/v1/voice/transcript", map[string]any{
		"callid": "cx-call-9", "cli": "+13125550199", "transcript": "pay with gift cards",
	})
	if w.Code != http.StatusAccepted {
		t.Fatalf("post: %d %s", w.Code, w.Body.String())
	}
	var saved struct {
		EventID int64 `json:"event_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil || saved.EventID == 0 {
		t.Fatalf("event: %s", w.Body.String())
	}
	ev := do(t, srv, http.MethodGet, "/v1/events/"+strconv.FormatInt(saved.EventID, 10), nil)
	if ev.Code != http.StatusOK {
		t.Fatalf("get: %d %s", ev.Code, ev.Body.String())
	}
	var out struct {
		Voice struct {
			Transcript string `json:"transcript"`
			CallID     string `json:"call_id"`
		} `json:"voice"`
	}
	if err := json.Unmarshal(ev.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Voice.Transcript != "pay with gift cards" || out.Voice.CallID != "cx-call-9" {
		t.Fatalf("%+v", out.Voice)
	}
}

func TestTranscriptScoreDebounce(t *testing.T) {
	var marks transcriptScore
	if !marks.due("c1", "hello gift cards", true) {
		t.Fatal("final")
	}
	if marks.due("c1", "hello gift cards", false) {
		t.Fatal("unchanged partial")
	}
}
