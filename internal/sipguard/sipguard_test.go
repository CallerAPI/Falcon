package sipguard

import (
	"runtime"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
)

const head = "OPTIONS sip:x@127.0.0.1 SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1\r\n" +
	"From: <sip:a@127.0.0.1>;tag=1\r\n" +
	"To: <sip:x@127.0.0.1>\r\n" +
	"Call-ID: guard\r\n" +
	"CSeq: 1 OPTIONS\r\n"

func datagram(contentLength, body string) []byte {
	if contentLength != "" {
		contentLength += "\r\n"
	}
	return []byte(head + contentLength + "\r\n" + body)
}

func TestDatagramBodyOverflows(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"no content length", datagram("", ""), false},
		{"zero", datagram("Content-Length: 0", ""), false},
		{"exact body", datagram("Content-Length: 3", "abc"), false},
		{"shorter than body", datagram("Content-Length: 2", "abc"), false},
		{"short body", datagram("Content-Length: 4", "abc"), true},
		{"4 GiB", datagram("Content-Length: 4294967295", ""), true},
		{"past uint64", datagram("Content-Length: 99999999999999999999999", ""), true},
		{"compact form", datagram("l: 70000", ""), true},
		{"lower case name", datagram("content-length:  9000 ", "x"), true},
		{"upper case name", datagram("CONTENT-LENGTH: 9000", "x"), true},
		{"space before colon", datagram("Content-Length : 9000", "x"), true},
		{"compact space before colon", datagram("L\t: 9000", "x"), true},

		{"space folded", datagram("Content-Length:\r\n 1073741824", ""), true},
		{"tab folded", datagram("Content-Length:\r\n\t1073741824", ""), true},
		{"multi line folded", datagram("Content-Length:\r\n \r\n\t \r\n  1073741824", ""), true},
		{"compact folded", datagram("l:\r\n 4294967295", ""), true},
		{"folded name", datagram("Content-Length\r\n : 1073741824", ""), true},
		{"folded small", datagram("Content-Length:\r\n 3", "abc"), false},
		{"folded other header", datagram("Subject: a\r\n Content-Length: 99", ""), false},
		{"continuation after start line", []byte("OPTIONS sip:x SIP/2.0\r\n Content-Length: 99\r\n\r\n"), true},

		{"not a number", datagram("Content-Length: abc", ""), true},
		{"empty value", datagram("Content-Length:", ""), true},
		{"negative", datagram("Content-Length: -1", ""), true},
		{"signed", datagram("Content-Length: +3", "abc"), true},
		{"comma list", datagram("Content-Length: 0, 3", "abc"), true},
		{"split digits", datagram("Content-Length: 1\r\n 0", "abc"), true},

		{"duplicate equal", datagram("Content-Length: 3\r\nl: 3", "abc"), false},
		{"duplicate conflicting", datagram("Content-Length: 0\r\nContent-Length: 3", "abc"), true},
		{"compact conflicting", datagram("l: 3\r\nContent-Length: 2", "abc"), true},

		{"lf only", []byte(strings.ReplaceAll(string(datagram("Content-Length: 1073741824", "")), "\r\n", "\n")), true},
		{"lf only small", []byte(strings.ReplaceAll(string(datagram("Content-Length: 3", "abc")), "\r\n", "\n")), false},
		{"lf header end", []byte(head + "Content-Length: 1073741824\n\n"), true},
		{"bare lf inside header", datagram("X-Pad: a\nContent-Length: 1073741824", ""), true},
		{"lf folded", []byte("OPTIONS sip:x SIP/2.0\nContent-Length:\n 1073741824\n\n"), true},

		{"no header end", []byte("OPTIONS sip:x SIP/2.0\r\nContent-Length: 0\r\n"), true},
		{"no header end no length", []byte("OPTIONS sip:x SIP/2.0\r\nVia: x\r\n"), false},
		{"unterminated length", []byte("OPTIONS sip:x SIP/2.0\r\nContent-Length: 0"), true},
		{"garbage", []byte("\x00\x01\x02"), false},
		{"keep alive", []byte("\r\n\r\n"), false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		if got := DatagramBodyOverflows(c.data); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestReadFilterOnlyDropsUDP(t *testing.T) {
	bad := datagram("Content-Length: 4294967295", "")
	folded := datagram("Content-Length:\r\n 4294967295", "")
	good := datagram("Content-Length: 0", "")
	for _, tc := range []struct {
		transport string
		data      []byte
		dropped   bool
	}{
		{"UDP", bad, true},
		{"udp", bad, true},
		{"UDP", folded, true},
		{"UDP", good, false},
		{"TCP", bad, false},
	} {
		out, err := ReadFilter(sip.TransportReadProps{Transport: tc.transport}, tc.data)
		if err != nil {
			t.Fatalf("%s: an error stops the sipgo read loop: %v", tc.transport, err)
		}
		if dropped := len(out) == 0; dropped != tc.dropped {
			t.Errorf("%s: dropped=%v want %v", tc.transport, dropped, tc.dropped)
		}
	}
}

// TestFoldedLengthReachesParser proves that the sipgo parser reads a body
// length from each folded header and that the filter drops the datagram
// first. ParseHeaders stops before the body, so the test allocates nothing
// large.
func TestFoldedLengthReachesParser(t *testing.T) {
	parser := sip.NewParser()
	for _, h := range []string{
		"Content-Length:\r\n 1073741824",
		"Content-Length:\r\n\t1073741824",
		"Content-Length:\r\n \r\n 1073741824",
		"l:\r\n 4294967295",
		"Content-Length\r\n : 1073741824",
	} {
		data := datagram(h, "")
		msg, _, err := parser.ParseHeaders(data, false)
		if err != nil {
			t.Fatalf("%q: sipgo rejects the headers, so the case proves nothing: %v", h, err)
		}
		cl := msg.ContentLength()
		if cl == nil || *cl < 1<<30 {
			t.Fatalf("%q: sipgo read length %v", h, cl)
		}
		if out, _ := ReadFilter(sip.TransportReadProps{Transport: "udp"}, data); len(out) != 0 {
			t.Errorf("%q: filter passed a datagram that declares %d body bytes", h, *cl)
		}
	}
}

// TestParserBehindFilterAllocatesLittle runs the real sipgo parser on what
// the filter lets through. 64 MiB is enough to see a bypass and small
// enough for CI if the filter regresses.
func TestParserBehindFilterAllocatesLittle(t *testing.T) {
	for _, h := range []string{
		"Content-Length:\r\n 67108864",
		"l:\r\n\t67108864",
		"Content-Length: 67108864",
	} {
		data := datagram(h, "")
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		if out, _ := ReadFilter(sip.TransportReadProps{Transport: "udp"}, data); len(out) != 0 {
			_, _ = sip.ParseMessage(out)
		}
		runtime.ReadMemStats(&after)
		if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
			t.Errorf("%q: parser allocated %d bytes behind the filter", h, grew)
		}
	}
}

// FuzzFilterCoversParser checks the filter against the real parser: every
// datagram the filter passes must declare no more body than it carries.
func FuzzFilterCoversParser(f *testing.F) {
	for _, s := range []string{
		string(datagram("Content-Length: 3", "abc")),
		string(datagram("Content-Length:\r\n 1073741824", "")),
		string(datagram("l:\r\n\t9", "")),
		"OPTIONS sip:x SIP/2.0\r\n Content-Length: 9\r\n\r\n",
		"OPTIONS sip:x SIP/2.0\nContent-Length: 9\n\n",
	} {
		f.Add([]byte(s))
	}
	parser := sip.NewParser()
	f.Fuzz(func(t *testing.T, data []byte) {
		if out, _ := ReadFilter(sip.TransportReadProps{Transport: "udp"}, data); len(out) == 0 {
			return
		}
		msg, n, err := parser.ParseHeaders(data, false)
		if err != nil || msg == nil {
			return
		}
		if cl := msg.ContentLength(); cl != nil && int(*cl) > len(data)-n {
			t.Fatalf("filter passed %q with length %d and %d body bytes", data, *cl, len(data)-n)
		}
	})
}
