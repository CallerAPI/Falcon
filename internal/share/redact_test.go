package share

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

const invite = "INVITE sip:+14155550123@carrier.example;user=phone SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK776\r\n" +
	"From: \"Kestrel\" <sip:+13125550188@203.0.113.9>;tag=a1\r\n" +
	"To: \"Jane Subscriber\" <sip:+14155550123@carrier.example>;tag=b2\r\n" +
	"t: <sip:14155550123@carrier.example>\r\n" +
	"P-Called-Party-ID: <sip:4155550123@carrier.example>\r\n" +
	"Diversion: <sip:+14155550999@carrier.example>;reason=unconditional\r\n" +
	"History-Info: <sip:+14155550999@carrier.example>;index=1\r\n" +
	"Identity: eyJhbGciOiJFUzI1NiJ9.eyJkZXN0Ijp7InRuIjpbIjE0MTU1NTUwMTIzIl19fQ.sig;info=<https://cert.example/k.pem>;alg=ES256;ppt=shaken\r\n" +
	"X-Route-Hint: dn=14155550123;trunk=7\r\n" +
	"Contact: <sip:+13125550188@203.0.113.9:5060>\r\n" +
	"Call-ID: 1758360000-4155550123@203.0.113.9\r\n" +
	"User-Agent: sipcli/1.8\r\n" +
	"Content-Type: application/sdp\r\n" +
	"Content-Length: 142\r\n" +
	"\r\n" +
	"v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\nc=IN IP4 203.0.113.9\r\n" +
	"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9Cnp\r\n"

func event() store.Event {
	shaken, _ := json.Marshal(map[string]any{
		"present": true, "verstat": "TN-Validation-Passed", "attest": "A",
		"orig_tn": "13125550188", "dest_tn": []string{"14155550123"},
		"signature_ok": true, "chain_trusted": true, "dest_matches_to": true,
	})
	return store.Event{
		ReceivedAt: time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC),
		Action:     score.ActionReject,
		RiskScore:  91,
		SourceIP:   "203.0.113.9",
		From:       "+13125550188",
		To:         "+14155550123",
		CallID:     "1758360000-4155550123@203.0.113.9",
		UserAgent:  "sipcli/1.8",
		Attest:     "A",
		Verstat:    "TN-Validation-Passed",
		SignerSPC:  "8080",
		Reasons:    []score.Reason{{Code: "list_deny", Weight: 100, Detail: "deny rule matched number +14155550123"}},
		Shaken:     shaken,
		RawSIP:     invite,
		Switch:     "sbc-1",
	}
}

func TestRedactDropsSwitchSigning(t *testing.T) {
	ev := event()
	ev.Verstat = ""
	ev.Shaken, _ = json.Marshal(map[string]any{"present": false, "source": "switch", "attest": "A", "x5u": "https://cert.example/k.pem"})
	out := Redact(ev, []byte("k"))
	if out.Attest != "" || out.SignerSPC != "" || out.SignerName != "" || out.Shaken != nil {
		t.Fatalf("switch signing shared: %+v", out)
	}
}

func TestRedactHidesCalledPartyEverywhere(t *testing.T) {
	out := Redact(event(), []byte("k"))
	body, _ := json.Marshal(out)
	s := string(body)
	for _, leak := range []string{"4155550123", "5550123", "Jane Subscriber", "a=crypto", "eyJhbGciOiJFUzI1NiJ9", "4155550999"} {
		if strings.Contains(s, leak) {
			t.Fatalf("shared payload leaks %q:\n%s", leak, s)
		}
	}
	if out.To != Redacted {
		t.Fatalf("to = %q", out.To)
	}
	if out.From != "+13125550188" {
		t.Fatalf("from changed: %q", out.From)
	}
	for _, keep := range []string{"+13125550188", "203.0.113.9", "sipcli/1.8", "carrier.example", "sip:REDACTED@carrier.example", "Identity: REDACTED", "tag=b2", "Content-Length: 0"} {
		if !strings.Contains(out.RawSIP, keep) {
			t.Fatalf("raw SIP lost %q:\n%s", keep, out.RawSIP)
		}
	}
	if !strings.HasPrefix(out.RawSIP, "INVITE sip:REDACTED@carrier.example;user=phone SIP/2.0") {
		t.Fatalf("request uri not redacted: %q", strings.SplitN(out.RawSIP, "\r\n", 2)[0])
	}
	if strings.Contains(out.RawSIP, "v=0") {
		t.Fatal("SDP body was shared")
	}
	if out.Reasons[0].Detail != "deny rule matched number REDACTED" {
		t.Fatalf("reason detail = %q", out.Reasons[0].Detail)
	}
	if out.Shaken == nil || out.Shaken.Verstat != "TN-Validation-Passed" || !out.Shaken.DestMatch {
		t.Fatalf("shaken summary lost: %+v", out.Shaken)
	}
}

func TestRedactHMACIsPerKeyAndStable(t *testing.T) {
	a := Redact(event(), []byte("one"))
	b := Redact(event(), []byte("one"))
	c := Redact(event(), []byte("two"))
	if a.ToHMAC == "" || len(a.ToHMAC) != 16 {
		t.Fatalf("to_hmac = %q", a.ToHMAC)
	}
	if a.ToHMAC != b.ToHMAC {
		t.Fatal("same key, different hash")
	}
	if a.ToHMAC == c.ToHMAC {
		t.Fatal("different key, same hash")
	}
	if Redact(event(), nil).ToHMAC != "" {
		t.Fatal("no key must mean no hash")
	}
}

func TestRedactHidesFromWhenItEqualsTo(t *testing.T) {
	ev := event()
	ev.From = "+14155550123"
	out := Redact(ev, []byte("k"))
	if out.From != Redacted || !out.FromEqualsTo {
		t.Fatalf("from = %q equals = %v", out.From, out.FromEqualsTo)
	}
}

func TestRedactHidesFromWhenItContainsCalledDigits(t *testing.T) {
	ev := event()
	ev.To = "0000000"
	ev.From = "1111000000000000000000"
	ev.CallID = "000"
	ev.UserAgent = ev.To
	ev.Switch = ev.To
	ev.RawSIP = "000\r\n\r\n"
	ev.Reasons = []score.Reason{{Code: "x", Detail: "000"}}
	out := Redact(ev, []byte("k"))
	fields := []string{out.To, out.From, out.CallID, out.UserAgent, out.Switch, out.RawSIP}
	for _, r := range out.Reasons {
		fields = append(fields, r.Detail)
	}
	if strings.Contains(strings.Join(fields, "\n"), "0000000") {
		t.Fatalf("called digits leaked: %q", fields)
	}
	if out.From == ev.From {
		t.Fatalf("from still contains called zeros: %q", out.From)
	}
}

func TestRedactNonNumericSubscriber(t *testing.T) {
	ev := event()
	ev.To = "alice.ops"
	ev.RawSIP = "INVITE sip:alice.ops@pbx.example SIP/2.0\r\nTo: <sip:Alice.Ops@pbx.example>\r\nX-Note: for alice.ops\r\n\r\n"
	out := Redact(ev, nil)
	if strings.Contains(strings.ToLower(out.RawSIP), "alice") {
		t.Fatalf("subscriber user leaked:\n%s", out.RawSIP)
	}
}

func TestRedactLeavesResponsesAndShortNumbersAlone(t *testing.T) {
	ev := event()
	ev.To = "911"
	ev.RawSIP = "SIP/2.0 200 OK\r\nTo: <sip:911@psap.example>\r\nX-Seq: 1234567890\r\n\r\n"
	out := Redact(ev, nil)
	if !strings.HasPrefix(out.RawSIP, "SIP/2.0 200 OK") {
		t.Fatalf("status line changed: %q", out.RawSIP)
	}
	if !strings.Contains(out.RawSIP, "X-Seq: 1234567890") {
		t.Fatalf("unrelated digits were removed:\n%s", out.RawSIP)
	}
	if !strings.Contains(out.RawSIP, "To: <sip:REDACTED@psap.example>") {
		t.Fatalf("To header kept the user:\n%s", out.RawSIP)
	}
}
