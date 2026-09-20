package fingerprint

import (
	"testing"

	"github.com/callerapi/falcon/internal/sipmsg"
)

// FuzzCompute asserts fingerprinting never panics and is deterministic.
func FuzzCompute(f *testing.F) {
	f.Add(invite)
	f.Add("INVITE sip:x SIP/2.0\r\nVia: SIP/2.0/\r\nCSeq:\r\nContact:\r\n\r\nv=0\r\nm=audio\r\na=rtpmap:0\r\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		m, err := sipmsg.Parse(raw)
		if err != nil {
			return
		}
		a, b := Compute(m), Compute(m)
		if a != b {
			t.Fatalf("not deterministic: %s vs %s", a, b)
		}
		if a != "" && len(a) != 16 {
			t.Fatalf("length %d", len(a))
		}
	})
}
