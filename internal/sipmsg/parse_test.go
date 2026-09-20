package sipmsg

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseInviteHeaders(t *testing.T) {
	raw := "INVITE sip:+15551212@carrier.example SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 203.0.113.10:5060;branch=z9hG4bK776\r\n" +
		"Via: SIP/2.0/UDP 198.51.100.4;received=198.51.100.4\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: \"Alice\" <sip:+14155550100@origin.example>;tag=19283\r\n" +
		"To: <sip:+15551212@carrier.example>\r\n" +
		"Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Contact: <sip:+14155550100@10.0.0.8:5060>\r\n" +
		"P-Asserted-Identity: <sip:+14155550100@origin.example>\r\n" +
		"User-Agent: Asterisk PBX 20.5\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 12\r\n" +
		"\r\n" +
		"v=0\r\no=x\r\n"

	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Method != "INVITE" {
		t.Fatalf("method %q", m.Method)
	}
	if m.Get("User-Agent") != "Asterisk PBX 20.5" {
		t.Fatalf("ua %q", m.Get("User-Agent"))
	}
	snap := SnapshotFrom(m, "203.0.113.10")
	if snap.FromUser != "+14155550100" {
		t.Fatalf("from %q", snap.FromUser)
	}
	if snap.ToUser != "+15551212" {
		t.Fatalf("to %q", snap.ToUser)
	}
	if snap.ViaHops != 2 {
		t.Fatalf("via hops %d", snap.ViaHops)
	}
	if snap.ViaReceived != "198.51.100.4" {
		t.Fatalf("received %q", snap.ViaReceived)
	}
	if snap.ContactHost != "10.0.0.8" {
		t.Fatalf("contact host %q", snap.ContactHost)
	}
	if !snap.HasSDP {
		t.Fatal("expected sdp")
	}
}

func TestCompactHeadersAndFolding(t *testing.T) {
	raw := "INVITE sip:bob@biloxi.com SIP/2.0\n" +
		"f: Alice <sip:alice@atlanta.com>;tag=1\n" +
		"t: Bob\n" +
		" <sip:bob@biloxi.com>\n" +
		"i: fold-call-id\n" +
		"v: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK\n\n"

	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Get("To"), "bob@biloxi.com") {
		t.Fatalf("folded To %q", m.Get("To"))
	}
	if m.Get("Call-ID") != "fold-call-id" {
		t.Fatalf("call-id %q", m.Get("Call-ID"))
	}
	snap := SnapshotFrom(m, "192.0.2.1")
	if snap.FromUser != "alice" {
		t.Fatalf("from user %q", snap.FromUser)
	}
}

func TestParseIdentity(t *testing.T) {
	payload := map[string]any{
		"attest": "A",
		"origid": "de305d54-75b4-431b-adb2-eb6b9e546014",
		"iat":    1710000000,
		"orig":   map[string]any{"tn": "14155550100"},
		"dest":   map[string]any{"tn": []string{"15551212"}},
	}
	body, _ := json.Marshal(payload)
	jwt := "eyJhbGciOiJFUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(body) + ".c2ln"
	id := parseIdentity(jwt + ";info=<https://cert.example/a.crt>;alg=ES256")
	if !id.ValidJWT {
		t.Fatal("expected valid jwt")
	}
	if id.Attest != "A" {
		t.Fatalf("attest %q", id.Attest)
	}
	if id.OrigTN != "+14155550100" {
		t.Fatalf("orig %q", id.OrigTN)
	}
	if id.OrigID == "" {
		t.Fatal("missing origid")
	}
}

func TestNormalizeE164(t *testing.T) {
	cases := map[string]string{
		"+1 (415) 555-0100": "+14155550100",
		"004415551111":      "+4415551111",
		"alice":             "alice",
		"tel:+12125551212":  "+12125551212",
	}
	for in, want := range cases {
		if got := NormalizeE164(in); got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestEmptyRejected(t *testing.T) {
	if _, err := Parse("   "); err == nil {
		t.Fatal("expected error")
	}
}
