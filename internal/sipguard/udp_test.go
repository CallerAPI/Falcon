package sipguard

import (
	"bytes"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// TestUDPListenerSurvivesOversizedLengths sends each dropped case to a real
// sipgo UDP listener with the guard installed. After each datagram an
// OPTIONS must still get 200, the guard must count one drop, and the
// process must allocate less than 1 MiB for that datagram.
func TestUDPListenerSurvivesOversizedLengths(t *testing.T) {
	ua, err := sipgo.NewUA(
		sipgo.WithUserAgent("guard-test"),
		sipgo.WithUserAgentTransportLayerOptions(sip.WithTransportLayerReadFilter(ReadFilter)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ua.Close()
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatal(err)
	}
	srv.OnOptions(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = srv.ServeUDP(listener) }()

	conn, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	probe := func(seq int) {
		t.Helper()
		local := conn.LocalAddr().String()
		opt := "OPTIONS sip:guard@" + listener.LocalAddr().String() + " SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP " + local + ";branch=z9hG4bKprobe" + strconv.Itoa(seq) + ";rport\r\n" +
			"Max-Forwards: 70\r\n" +
			"From: <sip:probe@" + local + ">;tag=p" + strconv.Itoa(seq) + "\r\n" +
			"To: <sip:guard@" + listener.LocalAddr().String() + ">\r\n" +
			"Call-ID: probe-" + strconv.Itoa(seq) + "\r\n" +
			"CSeq: 1 OPTIONS\r\n" +
			"Content-Length: 0\r\n\r\n"
		if _, err := conn.Write([]byte(opt)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("listener did not answer OPTIONS %d: %v", seq, err)
		}
		if !bytes.HasPrefix(buf[:n], []byte("SIP/2.0 200")) {
			t.Fatalf("OPTIONS %d answer: %q", seq, buf[:n])
		}
	}

	probe(0)
	var ms runtime.MemStats
	seq := 0
	for _, tc := range guardCases() {
		if !tc.drop {
			continue
		}
		seq++
		data := []byte(strings.Replace(tc.data, "Call-ID: guard-1", "Call-ID: guard-"+strconv.Itoa(seq), 1))
		runtime.ReadMemStats(&ms)
		before, drops := ms.TotalAlloc, Dropped()
		if _, err := conn.Write(data); err != nil {
			t.Fatal(err)
		}
		probe(seq)
		runtime.ReadMemStats(&ms)
		if got := ms.TotalAlloc - before; got >= 1<<20 {
			t.Errorf("%s: allocated %d bytes, want under 1 MiB", tc.name, got)
		}
		if got := Dropped() - drops; got != 1 {
			t.Errorf("%s: guard dropped %d datagrams, want 1", tc.name, got)
		}
	}
	if seq == 0 {
		t.Fatal("no dropped cases")
	}
}
