package bridge

import (
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
)

func rawOptions(local, bridge, callID, lengthHeader string) string {
	return "OPTIONS sip:falcon@" + bridge + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + local + ";branch=z9hG4bK" + callID + ";rport\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:scan@" + local + ">;tag=" + callID + "\r\n" +
		"To: <sip:falcon@" + bridge + ">\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		lengthHeader + "\r\n\r\n"
}

// A folded Content-Length that reaches the sipgo datagram parser makes it
// allocate the declared body in this process. The bridge must drop the
// datagram before the parser sees it and keep answering.
func TestBridgeDropsFoldedContentLengthBeforeParse(t *testing.T) {
	h := newHarness(t, options{action: score.ActionAllow})
	conn, err := net.DialUDP("udp", nil, h.br.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local, bridge := conn.LocalAddr().String(), h.bridgeAddr()
	buf := make([]byte, 4096)
	for _, c := range []struct{ name, header string }{
		{"space folded", "Content-Length:\r\n 1073741824"},
		{"tab folded", "Content-Length:\r\n\t1073741824"},
		{"multi line folded", "Content-Length:\r\n \r\n\t4294967295"},
		{"folded compact", "l:\r\n 4294967295"},
		{"plain huge", "Content-Length: 4294967295"},
	} {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		if _, err := conn.Write([]byte(rawOptions(local, bridge, "fold"+strings.ReplaceAll(c.name, " ", ""), c.header))); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		runtime.ReadMemStats(&after)
		if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
			t.Fatalf("%s: the bridge allocated %d bytes for one datagram", c.name, grew)
		}
	}
	if _, err := conn.Write([]byte(rawOptions(local, bridge, "probe", "Content-Length: 0"))); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("the bridge stopped answering OPTIONS: %v", err)
		}
		if reply := string(buf[:n]); strings.Contains(reply, "Call-ID: probe") {
			if !strings.HasPrefix(reply, "SIP/2.0 200") {
				t.Fatalf("probe answer %q", reply)
			}
			return
		}
	}
}
