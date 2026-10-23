package sipguard

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/emiago/sipgo/sip"
)

const startLine = "INVITE sip:+14155550100@127.0.0.1 SIP/2.0\r\n"

const baseHeaders = "Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bKguard\r\n" +
	"From: <sip:+13125550188@127.0.0.1>;tag=g1\r\n" +
	"To: <sip:+14155550100@127.0.0.1>\r\n" +
	"Call-ID: guard-1\r\n" +
	"CSeq: 1 INVITE\r\n"

// message is a start line, the common headers, the length headers, the
// empty line, and the body.
func message(lengthHeaders, body string) string {
	return startLine + baseHeaders + lengthHeaders + "\r\n" + body
}

type guardCase struct {
	name string
	data string
	drop bool
}

func guardCases() []guardCase {
	return []guardCase{
		{"exact length", message("Content-Length: 5\r\n", "hello"), false},
		{"no length header", message("", "hello"), false},
		{"zero length", message("Content-Length: 0\r\n", ""), false},
		{"shorter length", message("Content-Length: 2\r\n", "hello"), false},
		{"compact length", message("l: 5\r\n", "hello"), false},
		{"equal duplicates", message("Content-Length: 5\r\nl: 5\r\n", "hello"), false},
		{"keep alive", "\r\n\r\n", false},
		{"folded name is another header", message("Content-\r\n Length: 4000000000\r\n", ""), false},
		{"no header end without length", startLine + baseHeaders, false},

		{"plain oversized", message("Content-Length: 4294967295\r\n", ""), true},
		{"oversized by one", message("Content-Length: 6\r\n", "hello"), true},
		{"upper case name", message("CONTENT-LENGTH: 100000\r\n", ""), true},
		{"whitespace around name", message("Content-Length \t: 100000\r\n", ""), true},
		{"space folded", message("Content-Length:\r\n 4000000000\r\n", ""), true},
		{"tab folded", message("Content-Length:\r\n\t4000000000\r\n", ""), true},
		{"multi line folded", message("Content-Length\r\n :\r\n\t \r\n 4000000000 \r\n", ""), true},
		{"compact folded", message("l:\r\n 4000000000\r\n", ""), true},
		{"compact upper case folded", message("L\r\n\t: 100000\r\n", ""), true},
		{"first header after start line keeps its whitespace", startLine + " Content-Length: 100000\r\n" + baseHeaders + "\r\n", true},
		{"first header after start line folds its continuation", startLine + " Content-Length:\r\n 100000\r\n" + baseHeaders + "\r\n", true},
		{"unparseable", message("Content-Length: abc\r\n", ""), true},
		{"negative", message("Content-Length: -1\r\n", ""), true},
		{"plus sign", message("Content-Length: +5\r\n", "hello"), true},
		{"comma list", message("Content-Length: 5, 5\r\n", "hello"), true},
		{"empty value", message("Content-Length:\r\n", ""), true},
		{"past 32 bits", message("Content-Length: 99999999999999999999\r\n", ""), true},
		{"conflicting duplicates", message("Content-Length: 0\r\nl: 5\r\n", "hello"), true},
		{"conflicting duplicates both fit", message("Content-Length: 1\r\nContent-Length: 2\r\n", "hello"), true},
		{"no header end", startLine + baseHeaders + "Content-Length: 0\r\n", true},
		{"lf only message", "INVITE sip:a@b SIP/2.0\nCall-ID: x\nContent-Length: 100000\n\n", true},
		{"lf inside a header line", message("Subject: x\nContent-Length: 100000\r\n", ""), true},
		{"lf folded", "INVITE sip:a@b SIP/2.0\nCall-ID: x\nContent-Length:\n 100000\n\n", true},
	}
}

func TestDrop(t *testing.T) {
	for _, tc := range guardCases() {
		t.Run(tc.name, func(t *testing.T) {
			if got := Drop([]byte(tc.data)); got != tc.drop {
				t.Fatalf("Drop = %v, want %v for %q", got, tc.drop, tc.data)
			}
		})
	}
}

// Each case that the guard keeps must also be one the parser reads with a
// body that fits. This keeps the test table honest about sipgo's grammar.
func TestKeptCasesFitInTheParser(t *testing.T) {
	for _, tc := range guardCases() {
		if tc.drop {
			continue
		}
		if over, ok := parserOversized([]byte(tc.data)); ok && over {
			t.Errorf("%s: kept, but the parser declares a body past the datagram", tc.name)
		}
	}
}

// The folding cases must be ones the parser reads as an oversized length.
// Otherwise the guard would be checking a grammar sipgo does not use.
func TestFoldedCasesAreOversizedInTheParser(t *testing.T) {
	for _, tc := range guardCases() {
		switch tc.name {
		case "space folded", "tab folded", "multi line folded", "compact folded", "compact upper case folded",
			"first header after start line keeps its whitespace", "first header after start line folds its continuation":
		default:
			continue
		}
		over, ok := parserOversized([]byte(tc.data))
		if !ok || !over {
			t.Errorf("%s: parser ok=%v oversized=%v, want an oversized length", tc.name, ok, over)
		}
	}
}

func TestReadFilterDropsOnUDPOnly(t *testing.T) {
	bad := []byte(message("Content-Length: 4000000000\r\n", ""))
	good := []byte(message("Content-Length: 5\r\n", "hello"))

	before := Dropped()
	out, err := ReadFilter(sip.TransportReadProps{Transport: "UDP"}, bad)
	if err != nil || out != nil {
		t.Fatalf("udp oversized: out=%q err=%v, want nil, nil", out, err)
	}
	if Dropped() != before+1 {
		t.Fatalf("Dropped = %d, want %d", Dropped(), before+1)
	}
	out, err = ReadFilter(sip.TransportReadProps{Transport: "udp"}, good)
	if err != nil || !bytes.Equal(out, good) {
		t.Fatalf("udp valid: out=%q err=%v, want the datagram", out, err)
	}
	for _, tr := range []string{"TCP", "TLS", "WS", "WSS"} {
		out, err = ReadFilter(sip.TransportReadProps{Transport: tr}, bad)
		if err != nil || !bytes.Equal(out, bad) {
			t.Fatalf("%s: out=%q err=%v, want the data unchanged", tr, out, err)
		}
	}
}

// parserOversized reads the header section with the sipgo parser. ok is
// false when the parser rejects the headers. over is true when the length
// the parser would size the body from is larger than the rest of data.
func parserOversized(data []byte) (over, ok bool) {
	msg, n, err := sip.NewParser().ParseHeaders(data, false)
	if err != nil || msg == nil {
		return false, false
	}
	cl := msg.ContentLength()
	if cl == nil {
		return false, true
	}
	return uint64(*cl) > uint64(len(data)-n), true
}

// FuzzDropCoversParser checks that every datagram whose parsed length runs
// past its end is one that Drop rejects.
func FuzzDropCoversParser(f *testing.F) {
	for _, tc := range guardCases() {
		f.Add([]byte(tc.data))
	}
	f.Add([]byte(message("Content-Length: "+strconv.Itoa(1<<20)+"\r\n", "")))
	f.Fuzz(func(t *testing.T, data []byte) {
		drop := Drop(data)
		if over, ok := parserOversized(data); ok && over && !drop {
			t.Fatalf("parser declares a body past the datagram and Drop kept it: %q", data)
		}
	})
}
