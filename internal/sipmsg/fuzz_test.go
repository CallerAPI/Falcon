package sipmsg

import "testing"

// FuzzParse asserts the parser never panics and that a parsed message
// round-trips into a snapshot without panicking either.
func FuzzParse(f *testing.F) {
	f.Add("INVITE sip:+14155550123@x SIP/2.0\r\nVia: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bK1\r\nFrom: <sip:+13125550188@y>;tag=1\r\nTo: <sip:+14155550123@x>\r\nCall-ID: a@b\r\nCSeq: 1 INVITE\r\nIdentity: eyJhbGciOiJFUzI1NiJ9.e30.sig;info=<https://c/k.pem>\r\nContent-Length: 0\r\n\r\n")
	f.Add("SIP/2.0 200 OK\r\n\r\n")
	f.Add("INVITE\r\n:\r\n \r\n\t\r\nX:\r\n\r\nbody")
	f.Add("")
	f.Add("\x00\xff\xfe")
	f.Fuzz(func(t *testing.T, raw string) {
		m, err := Parse(raw)
		if err != nil {
			return
		}
		_ = SnapshotFrom(m, "203.0.113.9")
		_ = m.Get("to")
		_ = m.All("via")
	})
}
