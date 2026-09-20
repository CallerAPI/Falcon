package score

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/sipmsg"
	"github.com/callerapi/falcon/internal/velocity"
)

func testEngine() *Engine {
	e := NewEngine(Thresholds{Flag: 40, Challenge: 60, Reject: 80}, Limits{Window: time.Minute, IP: 3, From: 3, Scan: 3})
	e.Now = func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) }
	return e
}

func TestCleanInviteIsAllow(t *testing.T) {
	eng := testEngine()
	raw := invite("+14155550100", "+15551212", "Asterisk PBX 20", passport("A", "14155550100", eng.Now().Add(-10*time.Second).Unix()), "70")
	m, err := sipmsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	res := eng.Score(sipmsg.SnapshotFrom(m, "203.0.113.9"), Enrichment{})
	if res.Action != ActionAllow {
		t.Fatalf("action %s score %d reasons %+v", res.Action, res.RiskScore, res.Reasons)
	}
}

func TestScannerReject(t *testing.T) {
	raw := invite("+14155550100", "+15551212", "friendly-scanner", "", "70")
	m, _ := sipmsg.Parse(raw)
	res := testEngine().Score(sipmsg.SnapshotFrom(m, "198.51.100.20"), Enrichment{})
	if res.Action != ActionReject {
		t.Fatalf("want reject, got %s score %d", res.Action, res.RiskScore)
	}
	if !hasCode(res, "scanner_user_agent") {
		t.Fatalf("missing scanner reason: %+v", res.Reasons)
	}
	if res.SwitchHints.AsteriskHangupCause != 21 {
		t.Fatalf("hangup cause %d", res.SwitchHints.AsteriskHangupCause)
	}
}

func TestFromPAIMismatch(t *testing.T) {
	raw := "INVITE sip:+15551212@ex SIP/2.0\n" +
		"From: <sip:+14155550100@ex>;tag=1\n" +
		"To: <sip:+15551212@ex>\n" +
		"P-Asserted-Identity: <sip:+19998887777@ex>\n" +
		"Call-ID: x\nUser-Agent: FreeSWITCH\nMax-Forwards: 70\n\n"
	m, _ := sipmsg.Parse(raw)
	res := testEngine().Score(sipmsg.SnapshotFrom(m, "203.0.113.2"), Enrichment{})
	if !hasCode(res, "from_pai_mismatch") {
		t.Fatalf("expected mismatch: %+v", res.Reasons)
	}
}

func TestShakenOrigMismatch(t *testing.T) {
	eng := testEngine()
	raw := invite("+14155550100", "+15551212", "Kamailio", passport("A", "19998887777", eng.Now().Unix()), "70")
	m, _ := sipmsg.Parse(raw)
	res := eng.Score(sipmsg.SnapshotFrom(m, "203.0.113.3"), Enrichment{})
	if !hasCode(res, "shaken_orig_mismatch") {
		t.Fatalf("expected orig mismatch: %+v", res.Reasons)
	}
}

func TestPremiumRate(t *testing.T) {
	raw := invite("+14155550100", "+19005551212", "Asterisk", "", "70")
	m, _ := sipmsg.Parse(raw)
	res := testEngine().Score(sipmsg.SnapshotFrom(m, "203.0.113.4"), Enrichment{})
	if !hasCode(res, "premium_rate_dest") {
		t.Fatalf("expected premium: %+v", res.Reasons)
	}
}

func TestVelocityFlood(t *testing.T) {
	eng := testEngine()
	eng.Vel = velocity.New(time.Minute)
	raw := invite("+14155550100", "+15550001", "Asterisk", "", "70")
	m, _ := sipmsg.Parse(raw)
	snap := sipmsg.SnapshotFrom(m, "198.51.100.77")
	var last Result
	for i := 0; i < 5; i++ {
		last = eng.Score(snap, Enrichment{})
	}
	if !hasCode(last, "source_invite_flood") {
		t.Fatalf("expected flood: %+v", last.Reasons)
	}
}

func TestFeedAndFirewallUpsell(t *testing.T) {
	raw := invite("+14155550100", "+15551212", "Asterisk", "", "70")
	m, _ := sipmsg.Parse(raw)
	res := testEngine().Score(sipmsg.SnapshotFrom(m, "203.0.113.8"), Enrichment{
		FeedURL:     "https://callerapi.com",
		FirewallURL: "https://callerapi.com/sip-firewall",
	})
	if res.Upsell.SpamFeed.Connected || res.Upsell.VoiceFirewall.Connected {
		t.Fatal("addons should be disconnected")
	}
	if res.Upsell.SpamFeed.URL == "" || res.Upsell.VoiceFirewall.URL == "" {
		t.Fatal("expected upsell urls")
	}

	res = testEngine().Score(sipmsg.SnapshotFrom(m, "203.0.113.8"), Enrichment{FeedEnabled: true, FeedHit: true})
	if !hasCode(res, "spam_feed_hit") {
		t.Fatalf("expected feed hit: %+v", res.Reasons)
	}
	if res.Action != ActionReject || res.RiskScore != 100 || res.SIPStatus != 603 {
		t.Fatalf("spam feed hit must hard-reject, got action=%s score=%d sip=%d", res.Action, res.RiskScore, res.SIPStatus)
	}
	if res.Headers["X-Falcon-Block"] != "spam_feed" {
		t.Fatalf("expected X-Falcon-Block=spam_feed, got %v", res.Headers)
	}
}

func TestAnonymousWithoutPAI(t *testing.T) {
	raw := "INVITE sip:+15551212@ex SIP/2.0\n" +
		"From: \"Anonymous\" <sip:anonymous@anonymous.invalid>;tag=1\n" +
		"To: <sip:+15551212@ex>\nCall-ID: x\nUser-Agent: X\nMax-Forwards: 70\n\n"
	m, _ := sipmsg.Parse(raw)
	res := testEngine().Score(sipmsg.SnapshotFrom(m, "203.0.113.1"), Enrichment{})
	if !hasCode(res, "anonymous_from_no_pai") {
		t.Fatalf("expected anonymous: %+v", res.Reasons)
	}
}

func hasCode(res Result, code string) bool {
	for _, r := range res.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

func invite(from, to, ua, identity, mf string) string {
	var b strings.Builder
	b.WriteString("INVITE sip:" + to + "@ex SIP/2.0\n")
	b.WriteString("Via: SIP/2.0/UDP 203.0.113.9;branch=z9hG4bK1\n")
	b.WriteString("From: <sip:" + from + "@ex>;tag=1\n")
	b.WriteString("To: <sip:" + to + "@ex>\n")
	b.WriteString("Call-ID: test-call\n")
	b.WriteString("CSeq: 1 INVITE\n")
	b.WriteString("Contact: <sip:" + from + "@203.0.113.9:5060>\n")
	b.WriteString("User-Agent: " + ua + "\n")
	b.WriteString("Max-Forwards: " + mf + "\n")
	b.WriteString("Content-Type: application/sdp\n")
	if identity != "" {
		b.WriteString("Identity: " + identity + "\n")
	}
	b.WriteString("\nv=0\no=- 0 0 IN IP4 203.0.113.9\ns=-\nc=IN IP4 203.0.113.9\nt=0 0\nm=audio 10000 RTP/AVP 0\n")
	return b.String()
}

func passport(attest, orig string, iat int64) string {
	payload, _ := json.Marshal(map[string]any{
		"attest": attest,
		"origid": "11111111-1111-1111-1111-111111111111",
		"iat":    iat,
		"orig":   map[string]any{"tn": orig},
		"dest":   map[string]any{"tn": []string{"15551212"}},
	})
	return "eyJhbGciOiJFUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}
