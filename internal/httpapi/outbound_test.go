package httpapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/voice"
)

func outboundInvite(from, to, callID string) map[string]any {
	return map[string]any{
		"direction": "outbound", "customer": "acme", "source_ip": "10.0.0.5", "switch": "fs-1",
		"method": "INVITE", "request_uri": "sip:" + to + "@carrier.example",
		"headers": map[string]string{
			"From": "<sip:" + from + "@10.0.0.5>;tag=1", "To": "<sip:" + to + "@carrier.example>",
			"Call-ID": callID, "CSeq": "1 INVITE", "User-Agent": "Asterisk PBX 20", "Max-Forwards": "70",
			"Contact": "<sip:" + from + "@10.0.0.5>", "Content-Type": "application/sdp",
		},
		"body": "v=0\r\no=- 1 1 IN IP4 10.0.0.5\r\ns=-\r\nc=IN IP4 10.0.0.5\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\n",
	}
}

func screenJSON(t *testing.T, srv *Server, body map[string]any) score.Result {
	t.Helper()
	w := do(t, srv, http.MethodPost, "/v1/screen", body)
	if w.Code != 200 {
		t.Fatalf("screen: %d %s", w.Code, w.Body.String())
	}
	var res score.Result
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	time.Sleep(30 * time.Millisecond) // the insert is asynchronous
	return res
}

func withHook(t *testing.T, srv *Server) *[]map[string]any {
	t.Helper()
	var got []map[string]any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		got = append(got, m)
	}))
	t.Cleanup(hook.Close)
	th := alerts.Defaults()
	th.WebhookURL = hook.URL
	b, _ := json.Marshal(th)
	_ = srv.Store.KVSet(context.Background(), kvAlertSettings, string(b))
	srv.Alerts = &alerts.Watcher{Sources: alerts.Sources{Store: srv.Store, Thresholds: srv.AlertThresholds}}
	return &got
}

func TestOutboundSpoofIsRejectedAndPaged(t *testing.T) {
	srv, _ := newTestServer(t)
	hooks := withHook(t, srv)
	if w := do(t, srv, http.MethodPut, "/v1/customers", map[string]any{"id": "acme", "name": "Acme Dialer", "dids": []string{"+13125550100", "+1312555*"}}); w.Code != 200 {
		t.Fatalf("put customer: %d %s", w.Code, w.Body.String())
	}
	ok := screenJSON(t, srv, outboundInvite("+13125550177", "+14155550100", "own-1"))
	if ok.Action == score.ActionReject || hasReason(ok, "caller_id_not_owned") {
		t.Fatalf("owned prefix rejected: %+v", ok.Reasons)
	}
	spoof := screenJSON(t, srv, outboundInvite("+18005551234", "+14155550100", "spoof-1"))
	if spoof.Action != score.ActionReject || spoof.Headers["X-Falcon-Block"] != "caller_id" || spoof.Signals.Direction != "outbound" || spoof.Signals.Customer != "acme" {
		t.Fatalf("spoof: %+v %v", spoof.Action, spoof.Headers)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(*hooks) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(*hooks) != 1 {
		t.Fatalf("spoof alert webhooks = %d", len(*hooks))
	}
	data := (*hooks)[0]["falcon"].(map[string]any)["data"].(map[string]any)
	if data["kind"] != "outbound_spoof" || data["customer_id"] != "acme" || data["calling_number"] != "+18005551234" || data["suggested_action"] == "" {
		t.Fatalf("webhook data: %v", data)
	}
	// Unknown customer: no inventory, no spoof verdict, still screened.
	body := outboundInvite("+18005551234", "+14155550100", "unknown-1")
	body["customer"] = "nobody"
	if res := screenJSON(t, srv, body); hasReason(res, "caller_id_not_owned") {
		t.Fatal("unknown customer treated as spoofing")
	}
}

func TestOutcomesSequentialDialingAndHoneypot(t *testing.T) {
	srv, _ := newTestServer(t)
	if w := do(t, srv, http.MethodPost, "/v1/rules", map[string]any{"kind": "honeypot", "subject": "number", "value": "+1415555999*", "note": "unassigned block"}); w.Code != http.StatusCreated {
		t.Fatalf("honeypot rule: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, srv, http.MethodPut, "/v1/customers", map[string]any{"id": "acme", "dids": []string{"+1312555*"}}); w.Code != 200 {
		t.Fatalf("put customer: %d", w.Code)
	}
	from := "+13125550188"
	var last score.Result
	for i := 0; i < 6; i++ {
		to := fmt.Sprintf("+1415555%04d", 100+i)
		last = screenJSON(t, srv, outboundInvite(from, to, fmt.Sprintf("seq-%d", i)))
		w := do(t, srv, http.MethodPost, "/v1/outcome", map[string]any{"call_id": fmt.Sprintf("seq-%d", i), "answered": i%3 == 0, "duration_s": 4, "hangup_cause": "NORMAL_CLEARING"})
		if w.Code != 200 {
			t.Fatalf("outcome: %d %s", w.Code, w.Body.String())
		}
	}
	if !hasReason(last, "sequential_dialing") || last.Signals.CallerDistinctCallees < 5 {
		t.Fatalf("sequential dialing not seen: %+v %+v", last.Reasons, last.Signals)
	}
	if !last.Sample || last.Headers["X-Falcon-Sample"] != "1" {
		t.Fatalf("sequential dialer was not sampled: %+v", last.Headers)
	}
	hp := screenJSON(t, srv, outboundInvite(from, "+14155559991", "hp-1"))
	if !hasReason(hp, "honeypot_target") || !hp.Signals.Honeypot {
		t.Fatalf("honeypot: %+v", hp.Reasons)
	}
	w := do(t, srv, http.MethodGet, "/v1/customers/acme", nil)
	var cust struct {
		Last struct {
			Calls, Completed, Answered int
		} `json:"last_24h"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &cust)
	if cust.Last.Calls < 6 || cust.Last.Completed != 6 || cust.Last.Answered != 2 {
		t.Fatalf("customer activity: %+v (%s)", cust.Last, w.Body.String())
	}
	if w := do(t, srv, http.MethodPost, "/v1/outcome", map[string]any{"call_id": "nope", "answered": true}); w.Code != http.StatusNotFound {
		t.Fatalf("unknown call id: %d", w.Code)
	}
}

func testWAV(seed float64) []byte {
	rate, secs := 8000, 12
	n := rate * secs
	data := make([]byte, 0, n*4)
	for i := 0; i < n; i++ {
		tm := float64(i) / float64(rate)
		var caller int16
		if math.Sin(tm*0.8+seed) > -0.3 {
			caller = int16(5000 * math.Sin(2*math.Pi*300*tm))
		}
		data = binary.LittleEndian.AppendUint16(data, uint16(caller))
		data = binary.LittleEndian.AppendUint16(data, uint16(int16(i%7-3)))
	}
	out := make([]byte, 44+len(data))
	copy(out, "RIFF")
	binary.LittleEndian.PutUint32(out[4:], uint32(36+len(data)))
	copy(out[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(out[16:], 16)
	binary.LittleEndian.PutUint16(out[20:], 1)
	binary.LittleEndian.PutUint16(out[22:], 2)
	binary.LittleEndian.PutUint32(out[24:], uint32(rate))
	binary.LittleEndian.PutUint32(out[28:], uint32(rate*4))
	binary.LittleEndian.PutUint16(out[32:], 4)
	binary.LittleEndian.PutUint16(out[34:], 16)
	copy(out[36:], "data")
	binary.LittleEndian.PutUint32(out[40:], uint32(len(data)))
	copy(out[44:], data)
	return out
}

type fakeProvider struct{ calls int }

func (f *fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) Analyse(_ context.Context, _ []byte, _ voice.Meta) (voice.Verdict, error) {
	f.calls++
	return voice.Verdict{Transcript: "this is the irs, you owe back taxes, pay now with gift cards", Category: "Tax Collection", Score: 0.93, Summary: "IRS impersonation demanding gift cards"}, nil
}

func TestAudioClipRepeatDetectionAndClassification(t *testing.T) {
	srv, _ := newTestServer(t)
	hooks := withHook(t, srv)
	fp := &fakeProvider{}
	srv.VoiceProvider = fp
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("robo-%d", i)
		screenJSON(t, srv, outboundInvite("+13125550199", fmt.Sprintf("+1415555%04d", 200+i), id))
		req := httptest.NewRequest(http.MethodPost, "/v1/audio?call_id="+id, bytes.NewReader(testWAV(1.0)))
		req.Header.Set("Content-Type", "audio/wav")
		req.Header.Set("X-Falcon-Token", "secret")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("audio %d: %d %s", i, w.Code, w.Body.String())
		}
		var out struct {
			Repeat   int `json:"repeat_count"`
			Features voice.Features
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if out.Repeat != i || !out.Features.Monologue {
			t.Fatalf("clip %d: repeat=%d features=%+v", i, out.Repeat, out.Features)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if list, _ := srv.Store.VoiceSamples(context.Background(), 10); len(list) == 3 && list[0].Category != "" && list[2].Category != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	list, _ := srv.Store.VoiceSamples(context.Background(), 10)
	if len(list) != 3 || list[0].Category != "Tax Collection" || !strings.Contains(list[0].Transcript, "irs") || fp.calls != 3 {
		t.Fatalf("samples: %+v calls=%d", list, fp.calls)
	}
	kinds := map[string]bool{}
	for _, h := range *hooks {
		d := h["falcon"].(map[string]any)["data"].(map[string]any)
		kinds[d["kind"].(string)] = true
	}
	if !kinds["voice_scam"] || !kinds["repeat_recording"] {
		t.Fatalf("webhook kinds: %v", kinds)
	}
	w := do(t, srv, http.MethodGet, fmt.Sprintf("/v1/events/%d", list[0].EventID), nil)
	if !strings.Contains(w.Body.String(), `"voice"`) || strings.Contains(w.Body.String(), "REDACTED") {
		t.Fatalf("event view lacks voice: %s", w.Body.String()[:200])
	}
	// A clip without a token is refused even when the query token is set.
	req := httptest.NewRequest(http.MethodPost, "/v1/audio?call_id=robo-0&token=secret", bytes.NewReader(testWAV(1.0)))
	req.Header.Set("Content-Type", "audio/wav")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("query token accepted for audio upload: %d", rec.Code)
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

var _ = store.Outcome{}
