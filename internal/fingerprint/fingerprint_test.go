package fingerprint

import (
	"strings"
	"testing"

	"github.com/callerapi/falcon/internal/sipmsg"
)

const invite = "INVITE sip:+14155550123@carrier.example SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 203.0.113.9:5060;rport;branch=z9hG4bK-524287-1---abc\r\n" +
	"Max-Forwards: 70\r\n" +
	"Contact: <sip:+13125550188@203.0.113.9:5060;transport=udp>\r\n" +
	"To: <sip:+14155550123@carrier.example>\r\n" +
	"From: <sip:+13125550188@203.0.113.9>;tag=a1b2c3d4\r\n" +
	"Call-ID: 3f2a9b1c7d8e4f50@203.0.113.9\r\n" +
	"CSeq: 1 INVITE\r\n" +
	"Allow: INVITE, ACK, CANCEL, BYE, OPTIONS\r\n" +
	"Supported: replaces, timer\r\n" +
	"User-Agent: sipcli/1.8\r\n" +
	"Content-Type: application/sdp\r\n" +
	"Content-Length: 200\r\n\r\n" +
	"v=0\r\no=root 1 1 IN IP4 203.0.113.9\r\ns=call\r\nc=IN IP4 203.0.113.9\r\nt=0 0\r\n" +
	"m=audio 4000 RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=ptime:20\r\na=sendrecv\r\n"

func TestFingerprintIgnoresNumbersAddressesAndIDs(t *testing.T) {
	a, _ := sipmsg.Parse(invite)
	swapped := strings.NewReplacer(
		"+14155550123", "+12125559999", "+13125550188", "+447700900123",
		"203.0.113.9", "198.51.100.77", "3f2a9b1c7d8e4f50", "9e8d7c6b5a4f3e21",
		"tag=a1b2c3d4", "tag=ffee0011", "4000", "5002",
	).Replace(invite)
	b, _ := sipmsg.Parse(swapped)
	if Compute(a) == "" || Compute(a) != Compute(b) {
		t.Fatalf("fingerprint changed with numbers and addresses: %s vs %s\n%s\n---\n%s", Compute(a), Compute(b), Describe(a), Describe(b))
	}
}

func TestFingerprintChangesWithToolHabits(t *testing.T) {
	a, _ := sipmsg.Parse(invite)
	base := Compute(a)
	for name, mutate := range map[string]func(string) string{
		"user agent":   func(s string) string { return strings.Replace(s, "sipcli/1.8", "Asterisk PBX 18.9", 1) },
		"header order": func(s string) string { return strings.Replace(s, "Max-Forwards: 70\r\nContact:", "Contact:", 1) + "" },
		"codec order":  func(s string) string { return strings.Replace(s, "RTP/AVP 0 8 101", "RTP/AVP 8 0 101", 1) },
		"allow list": func(s string) string {
			return strings.Replace(s, "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS", "Allow: INVITE, ACK, BYE", 1)
		},
		"call-id shape": func(s string) string {
			return strings.Replace(s, "3f2a9b1c7d8e4f50@203.0.113.9", "12345678901234567890", 1)
		},
	} {
		m, err := sipmsg.Parse(mutate(invite))
		if err != nil {
			t.Fatal(err)
		}
		if got := Compute(m); got == base {
			t.Fatalf("%s: fingerprint did not change", name)
		}
	}
}

func TestDescribeCarriesNoSubscriberData(t *testing.T) {
	m, _ := sipmsg.Parse(invite)
	d := Describe(m).String()
	for _, leak := range []string{"4155550123", "3125550188", "203.0.113.9", "3f2a9b1c7d8e4f50", "a1b2c3d4"} {
		if strings.Contains(d, leak) {
			t.Fatalf("describe leaks %q:\n%s", leak, d)
		}
	}
}
