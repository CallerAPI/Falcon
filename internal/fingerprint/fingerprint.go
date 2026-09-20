// Package fingerprint derives a stable identifier for the software that sent
// a SIP request, in the spirit of JA3 for TLS. It hashes the habits a tool
// cannot easily change without becoming a different tool: header order, the
// option lists it advertises, the shape of its identifiers, and the shape of
// its SDP. It never includes numbers, addresses, ports, keys, or times, so the
// same fingerprint is shared by every install that meets the same tool and it
// carries nothing about any subscriber.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"

	"github.com/callerapi/falcon/internal/sipmsg"
)

// valueHeaders contribute their (normalised) value, not only their presence.
var valueHeaders = map[string]bool{
	"user-agent":      true,
	"server":          true,
	"allow":           true,
	"supported":       true,
	"require":         true,
	"accept":          true,
	"max-forwards":    true,
	"content-type":    true,
	"privacy":         true,
	"allow-events":    true,
	"min-se":          true,
	"session-expires": true,
}

var compact = map[string]string{
	"t": "to", "f": "from", "i": "call-id", "v": "via", "m": "contact",
	"c": "content-type", "l": "content-length", "y": "identity", "k": "supported",
	"e": "content-encoding", "s": "subject", "u": "allow-events",
}

var (
	hexRun  = regexp.MustCompile(`^[0-9a-f]+$`)
	uuidRun = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	numRun  = regexp.MustCompile(`\d+`)
)

// Parts is the human-readable component list behind a fingerprint.
type Parts []string

// String joins the parts the way they are hashed.
func (p Parts) String() string { return strings.Join(p, "\n") }

// Compute returns the 16-hex fingerprint of a parsed message.
func Compute(m *sipmsg.Message) string {
	return Hash(Describe(m))
}

// Hash turns parts into the wire form.
func Hash(p Parts) string {
	if len(p) == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(p.String()))
	return hex.EncodeToString(sum[:])[:16]
}

// Describe lists the components in order. Exposed so an operator can see
// why two tools share a fingerprint.
func Describe(m *sipmsg.Message) Parts {
	if m == nil {
		return nil
	}
	var p Parts
	p = append(p, "method="+strings.ToLower(m.Method))

	order, values := headerOrder(m.Raw)
	p = append(p, "headers="+strings.Join(order, ","))
	for _, name := range order {
		if !valueHeaders[name] {
			continue
		}
		p = append(p, name+"="+normalise(values[name]))
	}

	if via := m.Get("via"); via != "" {
		p = append(p, "via="+viaShape(via))
	}
	if cid := m.Get("call-id"); cid != "" {
		p = append(p, "call-id="+idShape(cid))
	}
	if from := m.Get("from"); from != "" {
		p = append(p, "from-tag="+tagShape(from))
	}
	if cseq := m.Get("cseq"); cseq != "" {
		p = append(p, "cseq="+cseqShape(cseq))
	}
	if ct := m.Get("contact"); ct != "" {
		p = append(p, "contact="+contactShape(ct))
	}
	if body := strings.TrimSpace(m.Body); body != "" {
		p = append(p, sdpShape(body)...)
	}
	return p
}

// headerOrder reads header names in wire order from the raw message. The
// parsed map loses order, and order is the strongest tool signal.
func headerOrder(raw string) ([]string, map[string]string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head, _, _ := strings.Cut(raw, "\n\n")
	lines := strings.Split(head, "\n")
	var order []string
	values := map[string]string{}
	for i, line := range lines {
		if i == 0 || line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n := strings.ToLower(strings.TrimSpace(name))
		if full, ok := compact[n]; ok {
			n = full
		}
		order = append(order, n)
		if _, seen := values[n]; !seen {
			values[n] = strings.TrimSpace(value)
		}
	}
	return order, values
}

// normalise lowercases, collapses spaces, and sorts comma lists so ordering
// noise from proxies does not split one tool into many fingerprints. Numbers
// inside values (versions) are kept: a version is part of the tool.
func normalise(v string) string {
	v = strings.ToLower(strings.Join(strings.Fields(v), " "))
	if strings.Contains(v, ",") {
		parts := strings.Split(v, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		sort.Strings(parts)
		v = strings.Join(parts, ",")
	}
	return v
}

func viaShape(v string) string {
	v = strings.ToLower(v)
	var out []string
	if i := strings.Index(v, "sip/2.0/"); i >= 0 {
		rest := v[i+len("sip/2.0/"):]
		if j := strings.IndexAny(rest, " \t"); j >= 0 {
			rest = rest[:j]
		}
		out = append(out, rest)
	}
	for _, flag := range []string{"rport", "branch=z9hg4bk", "received", "alias"} {
		if strings.Contains(v, flag) {
			out = append(out, flag)
		}
	}
	return strings.Join(out, "+")
}

// idShape classifies an identifier by length bucket and alphabet.
func idShape(id string) string {
	id = strings.TrimSpace(id)
	local, host, hasAt := strings.Cut(id, "@")
	l := strings.ToLower(local)
	class := "mixed"
	switch {
	case uuidRun.MatchString(l):
		class = "uuid"
	case hexRun.MatchString(l):
		class = "hex"
	case numRun.MatchString(l) && numRun.ReplaceAllString(l, "") == "":
		class = "digits"
	case strings.ContainsAny(l, "-_."):
		class = "punct"
	}
	bucket := (len(local) + 7) / 8 * 8
	out := class + "/" + itoa(bucket)
	if hasAt {
		out += "@"
		if strings.Count(host, ".") >= 1 && numRun.ReplaceAllString(strings.ReplaceAll(host, ".", ""), "") == "" {
			out += "ip"
		} else {
			out += "host"
		}
	}
	return out
}

func tagShape(from string) string {
	lower := strings.ToLower(from)
	i := strings.Index(lower, ";tag=")
	if i < 0 {
		return "none"
	}
	tag := lower[i+5:]
	if j := strings.IndexAny(tag, ";> "); j >= 0 {
		tag = tag[:j]
	}
	return idShape(tag)
}

func cseqShape(cseq string) string {
	f := strings.Fields(cseq)
	if len(f) == 0 {
		return ""
	}
	n := f[0]
	switch {
	case n == "1":
		return "1"
	case n == "0":
		return "0"
	case len(n) <= 3:
		return "small"
	case len(n) <= 6:
		return "medium"
	default:
		return "large"
	}
}

func contactShape(ct string) string {
	l := strings.ToLower(ct)
	var out []string
	if strings.Contains(l, "transport=") {
		out = append(out, "transport")
	}
	if strings.Contains(l, "+sip.instance") {
		out = append(out, "instance")
	}
	if strings.Contains(l, "expires=") {
		out = append(out, "expires")
	}
	if strings.HasPrefix(strings.TrimSpace(l), "\"") {
		out = append(out, "display")
	}
	if len(out) == 0 {
		return "plain"
	}
	return strings.Join(out, "+")
}

// sdpShape keeps codec order, direction, ptime, and security attributes.
// Addresses, ports, keys, and session ids are left out.
func sdpShape(body string) Parts {
	var p Parts
	var codecs []string
	var attrs []string
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		val := line[2:]
		switch line[0] {
		case 'v':
			p = append(p, "sdp-v="+val)
		case 's':
			p = append(p, "sdp-s="+strings.ToLower(val))
		case 'o':
			f := strings.Fields(val)
			if len(f) > 0 {
				p = append(p, "sdp-o-user="+strings.ToLower(f[0]))
			}
		case 'm':
			f := strings.Fields(val)
			if len(f) >= 4 {
				p = append(p, "sdp-m="+strings.ToLower(f[0])+"/"+strings.ToLower(f[2])+":"+strings.Join(f[3:], ","))
			}
		case 'a':
			key, rest, _ := strings.Cut(val, ":")
			key = strings.ToLower(key)
			switch key {
			case "rtpmap":
				f := strings.Fields(rest)
				if len(f) >= 2 {
					codecs = append(codecs, strings.ToLower(f[1]))
				}
			case "ptime", "maxptime", "sendrecv", "sendonly", "recvonly", "inactive", "rtcp-mux", "fmtp":
				attrs = append(attrs, key)
			case "crypto":
				attrs = append(attrs, "crypto")
			case "fingerprint":
				attrs = append(attrs, "dtls")
			}
		}
	}
	if len(codecs) > 0 {
		p = append(p, "sdp-codecs="+strings.Join(codecs, ","))
	}
	if len(attrs) > 0 {
		sort.Strings(attrs)
		p = append(p, "sdp-attrs="+strings.Join(dedupe(attrs), ","))
	}
	return p
}

func dedupe(in []string) []string {
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
