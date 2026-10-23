package bridge

import (
	"bytes"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/sipguard"
)

// uriUser is the Request-URI user part of every test message. No digit
// of it may reach the log.
const uriUser = "+19998887777"

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog sends the process log to a buffer without timestamps, so a
// digit in a line can only come from the line itself.
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	out := &lockedBuffer{}
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(out)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return out
}

// strangerBridge runs a bridge whose peer list excludes loopback, so
// every test message comes from an unknown address.
func strangerBridge(t *testing.T) (*harness, *net.UDPConn) {
	t.Helper()
	h := newHarness(t, options{action: score.ActionChallenge, peers: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	conn, err := net.DialUDP("udp", nil, h.br.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return h, conn
}

func sendN(t *testing.T, conn *net.UDPConn, msg string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
}

// sipLines returns the log lines written by the sipgo logger.
func sipLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "level=") {
			lines = append(lines, l)
		}
	}
	return lines
}

// assertClean fails when any log line carries the Request-URI user part
// or a run of its digits, or when a sipgo line carries any digit.
func assertClean(t *testing.T, out string) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		for _, part := range []string{uriUser, "999", "888", "777"} {
			if strings.Contains(l, part) {
				t.Fatalf("log line carries %q: %s\nfull log:\n%s", part, l, out)
			}
		}
	}
	for _, l := range sipLines(out) {
		if strings.ContainsAny(l, "0123456789") {
			t.Fatalf("sipgo line carries a digit: %s", l)
		}
	}
}

// assertLimited fails when one sipgo message was logged more than once.
func assertLimited(t *testing.T, out string) {
	t.Helper()
	seen := map[string]int{}
	for _, l := range sipLines(out) {
		seen[l]++
		if seen[l] > 1 {
			t.Fatalf("line logged %d times, want at most once: %s\nfull log:\n%s", seen[l], l, out)
		}
	}
}

func TestBridgeLogsAnUnparseableDatagramWithoutItsContent(t *testing.T) {
	out := captureLog(t)
	h, conn := strangerBridge(t)
	local := conn.LocalAddr().String()
	bad := "INVITE sip:" + uriUser + "@" + h.bridgeAddr() + " SIP/2.0 x\r\n" +
		"Via: SIP/2.0/UDP " + local + ";branch=z9hG4bKbroken1;rport\r\n" +
		"From: <sip:" + uriUser + "@" + local + ">;tag=b1\r\n" +
		"Call-ID: broken-1@" + local + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n\r\n"
	sendN(t, conn, bad, 20)
	waitFor(t, "parse failure logged", 2*time.Second, func() bool {
		return strings.Contains(out.String(), "parse")
	})
	time.Sleep(200 * time.Millisecond)

	got := out.String()
	if n := strings.Count(got, "parse"); n != 1 {
		t.Fatalf("want one parse failure line for 20 datagrams, got %d:\n%s", n, got)
	}
	assertClean(t, got)
	for _, raw := range []string{"INVITE", "z9hG4bK", "broken-1", "Call-ID"} {
		if strings.Contains(got, raw) {
			t.Fatalf("log carries %q:\n%s", raw, got)
		}
	}
}

func TestBridgeLogsMalformedRequestsWithoutTheRequestURI(t *testing.T) {
	cases := []struct {
		name   string
		header func(local, bridge string) string
		logs   bool
	}{
		{"missing Via", func(local, bridge string) string {
			return "From: <sip:" + uriUser + "@" + local + ">;tag=v1\r\n" +
				"To: <sip:" + uriUser + "@" + bridge + ">\r\n" +
				"Call-ID: noVia@" + local + "\r\n" +
				"CSeq: 1 INVITE\r\n"
		}, true},
		{"missing CSeq", func(local, bridge string) string {
			return "Via: SIP/2.0/UDP " + local + ";branch=z9hG4bKnocseq;rport\r\n" +
				"From: <sip:" + uriUser + "@" + local + ">;tag=c1\r\n" +
				"To: <sip:" + uriUser + "@" + bridge + ">\r\n" +
				"Call-ID: noCSeq@" + local + "\r\n"
		}, true},
		{"old branch and no From tag", func(local, bridge string) string {
			return "Via: SIP/2.0/UDP " + local + ";branch=oldstyle;rport\r\n" +
				"From: <sip:" + uriUser + "@" + local + ">\r\n" +
				"To: <sip:" + uriUser + "@" + bridge + ">\r\n" +
				"Call-ID: oldBranch@" + local + "\r\n" +
				"CSeq: 1 INVITE\r\n"
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := captureLog(t)
			h, conn := strangerBridge(t)
			local := conn.LocalAddr().String()
			msg := "INVITE sip:" + uriUser + "@" + h.bridgeAddr() + " SIP/2.0\r\n" +
				tc.header(local, h.bridgeAddr()) +
				"Max-Forwards: 70\r\n" +
				"Content-Length: 0\r\n\r\n"
			sendN(t, conn, msg, 20)
			if tc.logs {
				waitFor(t, "malformed request logged", 2*time.Second, func() bool {
					return len(sipLines(out.String())) > 0
				})
			}
			time.Sleep(300 * time.Millisecond)
			got := out.String()
			assertClean(t, got)
			assertLimited(t, got)
		})
	}
}

func TestBridgeCountsStrayResponsesWithoutLogging(t *testing.T) {
	out := captureLog(t)
	h, conn := strangerBridge(t)
	local := conn.LocalAddr().String()
	res := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP " + h.bridgeAddr() + ";branch=z9hG4bKnotours\r\n" +
		"From: <sip:" + uriUser + "@" + h.bridgeAddr() + ">;tag=r1\r\n" +
		"To: <sip:" + uriUser + "@" + local + ">;tag=r2\r\n" +
		"Call-ID: stray@" + local + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n\r\n"
	before := sipguard.UnhandledResponses()
	sendN(t, conn, res, 100)
	waitFor(t, "stray responses counted", 3*time.Second, func() bool {
		return sipguard.UnhandledResponses()-before >= 100
	})
	time.Sleep(200 * time.Millisecond)
	got := out.String()
	if lines := sipLines(got); len(lines) != 0 {
		t.Fatalf("stray responses were logged:\n%s", strings.Join(lines, "\n"))
	}
	assertClean(t, got)
}
