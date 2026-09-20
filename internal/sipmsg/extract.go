package sipmsg

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	reAngleURI = regexp.MustCompile(`(?i)<(sips?|tel):([^>]+)>`)
	reBareURI  = regexp.MustCompile(`(?i)(sips?|tel):([^;>\s]+)`)
	reViaHop   = regexp.MustCompile(`(?i)SIP/2\.0/`)
	reReceived = regexp.MustCompile(`(?i)[;,\s]received=([0-9a-f:.]+)`)
)

// Identity is the decoded STIR/SHAKEN PASSporT payload, without cert verify.
type Identity struct {
	Raw      string
	ValidJWT bool
	Attest   string
	OrigTN   string
	OrigID   string
	DestTN   []string
	IAT      int64
}

// Snapshot is the subset of a SIP request the scorer needs.
type Snapshot struct {
	Method      string
	RequestURI  string
	FromRaw     string
	FromUser    string
	FromHost    string
	ToRaw       string
	ToUser      string
	ToHost      string
	PAIUser     string
	RPIDUser    string
	Contact     string
	ContactHost string
	CallID      string
	UserAgent   string
	Privacy     string
	MaxForwards int
	ViaHops     int
	ViaReceived string
	Identity    Identity
	HasSDP      bool
	SDPZero     bool
	SourceIP    string
}

func SnapshotFrom(m *Message, sourceIP string) Snapshot {
	s := Snapshot{
		Method:      m.Method,
		RequestURI:  m.RequestURI,
		FromRaw:     m.Get("From"),
		ToRaw:       m.Get("To"),
		Contact:     m.Get("Contact"),
		CallID:      m.Get("Call-ID"),
		UserAgent:   m.Get("User-Agent"),
		Privacy:     m.Get("Privacy"),
		MaxForwards: atoiDefault(m.Get("Max-Forwards"), -1),
		ViaHops:     countViaHops(m.All("Via")),
		ViaReceived: firstReceived(m.All("Via")),
		Identity:    parseIdentity(m.Get("Identity")),
		HasSDP:      strings.Contains(strings.ToLower(m.Get("Content-Type")), "sdp") || looksLikeSDP(m.Body),
		SDPZero:     strings.Contains(m.Body, "c=IN IP4 0.0.0.0") || strings.Contains(m.Body, "c=IN IP6 ::"),
		SourceIP:    HostOnly(sourceIP),
	}
	s.FromUser, s.FromHost = uriUserHost(s.FromRaw)
	s.ToUser, s.ToHost = uriUserHost(s.ToRaw)
	if s.ToUser == "" {
		s.ToUser, s.ToHost = uriUserHost(s.RequestURI)
	}
	s.PAIUser, _ = uriUserHost(m.Get("P-Asserted-Identity"))
	s.RPIDUser, _ = uriUserHost(m.Get("Remote-Party-ID"))
	_, s.ContactHost = uriUserHost(s.Contact)
	if s.ContactHost == "" {
		s.ContactHost = hostOnly(s.Contact)
	}
	return s
}

func countViaHops(vias []string) int {
	n := 0
	for _, v := range vias {
		n += len(reViaHop.FindAllStringIndex(v, -1))
	}
	if n == 0 {
		return len(vias)
	}
	return n
}

func firstReceived(vias []string) string {
	for _, v := range vias {
		if m := reReceived.FindStringSubmatch(v); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

func uriUserHost(raw string) (user, host string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if m := reAngleURI.FindStringSubmatch(raw); len(m) == 3 {
		return splitUserHost(m[1], m[2])
	}
	if m := reBareURI.FindStringSubmatch(raw); len(m) == 3 {
		return splitUserHost(m[1], m[2])
	}
	return "", ""
}

func splitUserHost(scheme, rest string) (user, host string) {
	rest = strings.TrimSpace(rest)
	if strings.EqualFold(scheme, "tel") {
		return NormalizeE164(rest), ""
	}
	userPart, hostPart, ok := strings.Cut(rest, "@")
	if !ok {
		return NormalizeE164(rest), ""
	}
	hostPart, _, _ = strings.Cut(hostPart, ";")
	hostPart, _, _ = strings.Cut(hostPart, ">")
	if i := strings.LastIndexByte(hostPart, ':'); i > 0 && !strings.Contains(hostPart, "]") {
		hostPart = hostPart[:i]
	}
	return NormalizeE164(userPart), strings.Trim(hostPart, "[]")
}

// HostOnly reduces a source address to its IP. Switches often report the
// peer as "ip:port" (Asterisk CHANNEL(pjsip,remote_addr), Kamailio $si:$sp).
// A port left on the address makes every IP lookup miss.
func HostOnly(addr string) string {
	return hostOnly(addr)
}

func hostOnly(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "@"); i >= 0 {
		raw = raw[i+1:]
	}
	raw = strings.Trim(raw, "<>")
	raw, _, _ = strings.Cut(raw, ";")
	if i := strings.LastIndexByte(raw, ':'); i > 0 && net.ParseIP(raw) == nil {
		raw = raw[:i]
	}
	return strings.Trim(raw, "[]")
}

// NormalizeE164 keeps digits and a leading plus.
func NormalizeE164(num string) string {
	n := strings.TrimSpace(num)
	if n == "" {
		return ""
	}
	if i := strings.IndexAny(n, ";?"); i >= 0 {
		n = n[:i]
	}
	n = strings.TrimPrefix(n, "tel:")
	hasPlus := strings.HasPrefix(n, "+") || strings.HasPrefix(n, "00")
	var b strings.Builder
	if strings.HasPrefix(n, "+") {
		b.WriteByte('+')
	}
	for _, r := range n {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" || out == "+" {
		// Non-numeric SIP user (alice, anonymous).
		cleaned := strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_' {
				return r
			}
			return -1
		}, num)
		return strings.ToLower(cleaned)
	}
	if strings.HasPrefix(out, "00") {
		out = "+" + out[2:]
		hasPlus = true
	}
	if hasPlus && !strings.HasPrefix(out, "+") {
		out = "+" + out
	}
	if !strings.HasPrefix(out, "+") {
		digits := out
		if len(digits) >= 8 && len(digits) <= 15 {
			out = "+" + digits
		}
	}
	return out
}

func parseIdentity(raw string) Identity {
	id := Identity{Raw: strings.TrimSpace(raw)}
	if id.Raw == "" {
		return id
	}
	jwt := id.Raw
	if i := strings.IndexByte(jwt, ';'); i >= 0 {
		jwt = jwt[:i]
	}
	jwt = strings.TrimSpace(jwt)
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return id
	}
	payload, err := decodeB64URL(parts[1])
	if err != nil {
		return id
	}
	var body struct {
		Attest string `json:"attest"`
		OrigID string `json:"origid"`
		IAT    int64  `json:"iat"`
		Orig   struct {
			TN string `json:"tn"`
		} `json:"orig"`
		Dest struct {
			TN []string `json:"tn"`
		} `json:"dest"`
	}
	if json.Unmarshal(payload, &body) != nil {
		return id
	}
	id.ValidJWT = true
	id.Attest = strings.ToUpper(strings.TrimSpace(body.Attest))
	id.OrigTN = NormalizeE164(body.Orig.TN)
	id.OrigID = body.OrigID
	id.IAT = body.IAT
	for _, tn := range body.Dest.TN {
		id.DestTN = append(id.DestTN, NormalizeE164(tn))
	}
	return id
}

func decodeB64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func looksLikeSDP(body string) bool {
	return strings.HasPrefix(strings.TrimSpace(body), "v=0")
}

func atoiDefault(s string, fallback int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}
