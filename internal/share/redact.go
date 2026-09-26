// Package share prepares screening events for CallerAPI telemetry. The called
// party is the operator's subscriber and never leaves the host: the number is
// replaced with REDACTED wherever it appears, the SDP body is dropped, and the
// PASSporT (which carries the called number in its dest claim) is removed.
package share

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/shaken"
	"github.com/callerapi/falcon/internal/store"
)

// Redacted is the placeholder that replaces the called party everywhere.
const Redacted = "REDACTED"

// Event is the shape Falcon sends. Field names are the wire format.
type Event struct {
	ReceivedAt string `json:"received_at"`
	Action     string `json:"action"`
	RiskScore  int    `json:"risk_score"`
	SourceIP   string `json:"source_ip"`
	From       string `json:"from"`
	// To is always Redacted. ToHMAC is a keyed hash with a per-install
	// secret, so one install's fan-out can be counted without the number
	// and without joining across installs.
	To           string `json:"to"`
	ToHMAC       string `json:"to_hmac,omitempty"`
	FromEqualsTo bool   `json:"from_equals_to,omitempty"`
	CallID       string `json:"call_id"`
	UserAgent    string `json:"user_agent"`
	Attest       string `json:"shaken_attest,omitempty"`
	Verstat      string `json:"verstat,omitempty"`
	SignerSPC    string `json:"signer_spc,omitempty"`
	SignerName   string `json:"signer_name,omitempty"`
	Provider     string `json:"provider,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	Direction    string `json:"direction,omitempty"`
	// CustomerHMAC is a keyed hash of the operator's account label, so
	// one install's customers can be told apart without naming them.
	CustomerHMAC  string         `json:"customer_hmac,omitempty"`
	Answered      *bool          `json:"answered,omitempty"`
	DurationS     *int           `json:"duration_s,omitempty"`
	Honeypot      bool           `json:"honeypot,omitempty"`
	VoiceCategory string         `json:"voice_category,omitempty"`
	VoiceScore    float64        `json:"voice_score,omitempty"`
	Shaken        *Summary       `json:"shaken,omitempty"`
	Reasons       []score.Reason `json:"reasons"`
	RawSIP        string         `json:"raw_sip"`
	Switch        string         `json:"switch,omitempty"`
}

// Summary is the verification result without the dest claim.
type Summary struct {
	Present   bool     `json:"present"`
	Source    string   `json:"source,omitempty"`
	Alg       string   `json:"alg,omitempty"`
	X5U       string   `json:"x5u,omitempty"`
	Attest    string   `json:"attest,omitempty"`
	Verstat   string   `json:"verstat"`
	Signature bool     `json:"signature_ok"`
	Chain     bool     `json:"chain_trusted"`
	CertValid bool     `json:"cert_valid"`
	Revoked   bool     `json:"revoked"`
	Fresh     bool     `json:"fresh"`
	OrigMatch bool     `json:"orig_matches_from"`
	DestMatch bool     `json:"dest_matches_to"`
	Errors    []string `json:"errors,omitempty"`
}

// calledPartyHeaders name the operator's subscriber or a subscriber the call
// was forwarded through. Their URI user and display name are replaced whole.
var calledPartyHeaders = map[string]bool{
	"to":                true,
	"p-called-party-id": true,
	"diversion":         true,
	"history-info":      true,
	"referred-by":       true,
	"target-dialog":     true,
}

// droppedHeaders carry the called party in a form that cannot be edited in
// place. The PASSporT holds it in the dest claim.
var droppedHeaders = map[string]bool{
	"identity": true,
}

var compact = map[string]string{
	"t": "to",
	"f": "from",
	"i": "call-id",
	"v": "via",
	"m": "contact",
	"c": "content-type",
	"l": "content-length",
	"y": "identity",
}

// numberRun matches digits with the punctuation people put between them,
// so 415-555-0123 and (415) 555 0123 are caught along with 4155550123.
var numberRun = regexp.MustCompile(`\+?\d[\d\-. ()]{5,}\d`)

// Redact converts a stored event into the shareable form. key is the
// per-install HMAC secret. An empty key leaves ToHMAC empty.
func Redact(ev store.Event, key []byte) Event {
	called := digits(ev.To)
	calledUser := userPart(ev.To)
	out := Event{
		ReceivedAt:    ev.ReceivedAt.UTC().Format(time.RFC3339Nano),
		Action:        string(ev.Action),
		RiskScore:     ev.RiskScore,
		SourceIP:      ev.SourceIP,
		From:          ev.From,
		To:            Redacted,
		CallID:        ev.CallID,
		UserAgent:     ev.UserAgent,
		Attest:        ev.Attest,
		Verstat:       ev.Verstat,
		SignerSPC:     ev.SignerSPC,
		SignerName:    ev.SignerName,
		Provider:      ev.Provider,
		Fingerprint:   ev.Fingerprint,
		Switch:        ev.Switch,
		Direction:     ev.Direction,
		Answered:      ev.Answered,
		DurationS:     ev.DurationS,
		Honeypot:      ev.Honeypot,
		VoiceCategory: ev.VoiceCategory,
		VoiceScore:    ev.VoiceScore,
	}
	if len(key) > 0 && ev.Customer != "" {
		out.CustomerHMAC = keyedHash(key, "customer:"+ev.Customer)
	}
	if len(key) > 0 && called != "" {
		out.ToHMAC = keyedHash(key, called)
	}
	if called != "" && called == digits(ev.From) {
		// Neighbour spoofing with an exact match: the caller shows the
		// subscriber's own number. Sharing From would reveal To.
		out.From = Redacted
		out.FromEqualsTo = true
	}
	scrub := newScrubber(called, calledUser)
	// From can still carry the called digits as a run inside a longer
	// number. The same pass used on Call-ID applies here.
	if out.From != Redacted {
		out.From = scrub.text(ev.From)
	}
	// Some switches build the Call-ID from the called number.
	out.CallID = scrub.text(ev.CallID)
	out.UserAgent = scrub.text(ev.UserAgent)
	out.Switch = scrub.text(ev.Switch)
	out.Reasons = make([]score.Reason, 0, len(ev.Reasons))
	for _, r := range ev.Reasons {
		r.Detail = scrub.text(r.Detail)
		out.Reasons = append(out.Reasons, r)
	}
	out.Shaken = summarize(ev.Shaken)
	if out.Shaken != nil && out.Shaken.Source == shaken.SourceSwitch {
		// A switch can name any certificate. Signer reputation is built
		// only from PASSporTs Falcon verified.
		out.Attest, out.SignerSPC, out.SignerName, out.Shaken = "", "", "", nil
	}
	out.RawSIP = scrub.sip(ev.RawSIP)
	return out
}

func summarize(raw json.RawMessage) *Summary {
	if len(raw) == 0 {
		return nil
	}
	var s Summary
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return &s
}

type scrubber struct {
	called string
	tail   string
	user   string
}

func newScrubber(called, user string) scrubber {
	s := scrubber{called: called}
	if len(called) >= 7 {
		s.tail = called[len(called)-7:]
	}
	if len(user) >= 3 && digits(user) == "" {
		// Non-numeric subscriber user like "alice" or a hashed extension.
		s.user = asciiLower(user)
	}
	return s
}

// text replaces any digit run that is, ends with, or is contained in the
// called number. Seven digits is the shortest national number worth hiding
// and long enough to miss timestamps and Call-IDs in practice; a false hit
// only removes a number that was not the subscriber's.
func (s scrubber) text(in string) string {
	if in == "" {
		return in
	}
	if s.tail != "" {
		in = numberRun.ReplaceAllStringFunc(in, func(run string) string {
			d := digits(run)
			if len(d) < 7 {
				return run
			}
			// Ends with the subscriber's last seven digits, is a prefix of
			// the subscriber's number, or contains the whole number (an
			// extension-suffixed form). Privacy wins over a false hit.
			if strings.HasSuffix(d, s.tail) || strings.HasSuffix(s.called, d) || strings.Contains(d, s.called) {
				return Redacted
			}
			return run
		})
	}
	if s.user != "" {
		in = replaceFold(in, s.user, Redacted)
	}
	return in
}

// sip rewrites a raw SIP message: headers only, called-party headers
// replaced whole, the PASSporT dropped, and the digit pass over the rest.
func (s scrubber) sip(raw string) string {
	if raw == "" {
		return ""
	}
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	headerPart, _, _ := strings.Cut(raw, "\n\n")
	lines := unfold(strings.Split(headerPart, "\n"))
	out := make([]string, 0, len(lines))
	for i, line := range lines {
		if i == 0 {
			out = append(out, s.text(redactStartLine(line)))
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			out = append(out, s.text(line))
			continue
		}
		canon := strings.ToLower(strings.TrimSpace(name))
		if full, ok := compact[canon]; ok {
			canon = full
		}
		switch {
		case droppedHeaders[canon]:
			out = append(out, strings.TrimSpace(name)+": "+Redacted)
		case calledPartyHeaders[canon]:
			out = append(out, strings.TrimSpace(name)+": "+redactNameAddr(strings.TrimSpace(value)))
		case canon == "content-length":
			out = append(out, strings.TrimSpace(name)+": 0")
		default:
			out = append(out, s.text(line))
		}
	}
	return strings.Join(out, "\r\n") + "\r\n\r\n"
}

func unfold(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l == "" {
			continue
		}
		if (l[0] == ' ' || l[0] == '\t') && len(out) > 0 {
			out[len(out)-1] += " " + strings.TrimSpace(l)
			continue
		}
		out = append(out, l)
	}
	return out
}

// redactStartLine hides the Request-URI user of a request. Responses pass.
func redactStartLine(line string) string {
	parts := strings.Fields(line)
	if len(parts) < 3 || strings.HasPrefix(parts[0], "SIP/") {
		return line
	}
	parts[1] = redactURIUser(parts[1])
	return strings.Join(parts, " ")
}

// redactNameAddr rewrites `"Name" <sip:user@host;p>;tag=x` as
// `<sip:REDACTED@host;p>;tag=x`, and bare URIs the same way.
func redactNameAddr(v string) string {
	if v == "" {
		return v
	}
	lt := strings.IndexByte(v, '<')
	gt := strings.LastIndexByte(v, '>')
	if lt >= 0 && gt > lt {
		return "<" + redactURIUser(v[lt+1:gt]) + ">" + v[gt+1:]
	}
	// Bare URI, possibly with params. A value with no scheme at all is a
	// bare number or name: hide all of it up to the first parameter.
	if out := redactURIUser(v); out != v || hasScheme(v) {
		return out
	}
	if i := strings.IndexByte(v, ';'); i >= 0 {
		return Redacted + v[i:]
	}
	return Redacted
}

func hasScheme(v string) bool {
	l := asciiLower(v)
	return strings.Contains(l, "sip:") || strings.Contains(l, "sips:") || strings.Contains(l, "tel:")
}

// asciiLower lowercases ASCII only, so byte offsets stay valid in the
// original string. strings.ToLower can change byte lengths.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// redactURIUser replaces the user part of sip:, sips:, and tel: URIs.
func redactURIUser(uri string) string {
	lower := asciiLower(uri)
	for _, scheme := range []string{"sips:", "sip:", "tel:"} {
		i := strings.Index(lower, scheme)
		if i < 0 {
			continue
		}
		start := i + len(scheme)
		rest := uri[start:]
		if scheme == "tel:" {
			end := strings.IndexAny(rest, ";>? ")
			if end < 0 {
				end = len(rest)
			}
			return uri[:start] + Redacted + rest[end:]
		}
		if at := strings.IndexByte(rest, '@'); at >= 0 {
			return uri[:start] + Redacted + rest[at:]
		}
		// sip:host with no user: nothing to hide.
		return uri
	}
	return uri
}

func userPart(to string) string {
	u := strings.TrimSpace(to)
	if i := strings.IndexByte(u, '@'); i >= 0 {
		u = u[:i]
	}
	for _, p := range []string{"sips:", "sip:", "tel:"} {
		u = strings.TrimPrefix(u, p)
	}
	return u
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func keyedHash(key []byte, value string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

func replaceFold(s, old, repl string) string {
	if old == "" {
		return s
	}
	var b strings.Builder
	lower := asciiLower(s)
	i := 0
	for {
		j := strings.Index(lower[i:], old)
		if j < 0 {
			b.WriteString(s[i:])
			return b.String()
		}
		b.WriteString(s[i : i+j])
		b.WriteString(repl)
		i += j + len(old)
	}
}
