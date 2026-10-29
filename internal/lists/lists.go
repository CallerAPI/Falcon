// Package lists holds the operator's own rules. A rule names a calling
// number, a source IP or CIDR, or a STIR/SHAKEN signer SPC. Deny is a hard
// reject. Allow skips scoring. International marks a peer that sends calls
// from outside the UK. Exempt skips only the UK mobile caller ID check.
// Rules live in the store and are indexed in memory, so a lookup costs a
// map read on every INVITE.
package lists

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Kind is allow or deny.
type Kind string

const (
	Allow Kind = "allow"
	Deny  Kind = "deny"
	// Honeypot marks a called number or prefix the operator has not
	// assigned to anyone. A call to it is unsolicited by definition.
	Honeypot Kind = "honeypot"
	// International marks a source address that sends calls from outside
	// the UK. It does not allow or deny the call.
	International Kind = "international"
	// Exempt skips the UK mobile caller ID check for a source address or
	// a signer SPC. Other scoring still runs.
	Exempt Kind = "exempt"
)

// Subject is what the rule matches.
type Subject string

const (
	Number Subject = "number"
	IP     Subject = "ip"
	SPC    Subject = "spc"
)

// Rule is one row.
type Rule struct {
	ID      int64   `json:"id"`
	Kind    Kind    `json:"kind"`
	Subject Subject `json:"subject"`
	Value   string  `json:"value"`
	Note    string  `json:"note,omitempty"`
	// Origin is local or fleet. Fleet rows are replaced on each pull.
	Origin    string    `json:"origin,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Hit is a matched rule.
type Hit struct {
	Rule
}

// Normalize validates and canonicalises a rule's value. Numbers keep digits
// and a leading plus. IPs become a prefix. SPCs are trimmed and uppercased.
func Normalize(r Rule) (Rule, error) {
	r.Value = strings.TrimSpace(r.Value)
	if r.Value == "" {
		return r, errors.New("value is required")
	}
	switch r.Kind {
	case Allow, Deny:
	case Honeypot:
		if r.Subject != Number {
			return r, errors.New("honeypot rules take a called number or a prefix ending in *")
		}
	case International:
		if r.Subject != IP {
			return r, errors.New("international rules take a source address or a range")
		}
	case Exempt:
		if r.Subject != IP && r.Subject != SPC {
			return r, errors.New("exempt rules take a source address or a signer code")
		}
	default:
		return r, errors.New("kind must be allow, deny, honeypot, international, or exempt")
	}
	switch r.Subject {
	case Number:
		prefix := strings.HasSuffix(r.Value, "*")
		r.Value = normalizeNumber(strings.TrimSuffix(r.Value, "*"))
		if r.Value == "" {
			return r, errors.New("number has no digits")
		}
		if prefix {
			if r.Kind != Honeypot {
				return r, errors.New("prefixes are only allowed on honeypot rules")
			}
			r.Value += "*"
		}
	case IP:
		p, err := parsePrefix(r.Value)
		if err != nil {
			return r, err
		}
		r.Value = p.String()
	case SPC:
		r.Value = strings.ToUpper(r.Value)
	default:
		return r, errors.New("subject must be number, ip, or spc")
	}
	return r, nil
}

// Index answers lookups. Rebuild it whenever rules change.
type Index struct {
	mu               sync.RWMutex
	honeypots        map[string]bool
	honeypotPrefixes []string
	numbers          map[string]Rule
	spcs             map[string]Rule
	byLen            map[int]map[netip.Prefix]Rule
	intl             map[int]map[netip.Prefix]struct{}
	exemptIP         map[int]map[netip.Prefix]struct{}
	exemptSPC        map[string]struct{}
	count            int
}

// NewIndex builds an index from rules. Deny wins when a value has both.
func NewIndex(rules []Rule, now time.Time) *Index {
	idx := &Index{
		numbers: map[string]Rule{}, spcs: map[string]Rule{}, byLen: map[int]map[netip.Prefix]Rule{}, honeypots: map[string]bool{},
		intl: map[int]map[netip.Prefix]struct{}{}, exemptIP: map[int]map[netip.Prefix]struct{}{}, exemptSPC: map[string]struct{}{},
	}
	for _, r := range rules {
		if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
			continue
		}
		idx.count++
		switch r.Kind {
		case Honeypot:
			v := strings.TrimPrefix(r.Value, "+")
			if strings.HasSuffix(v, "*") {
				idx.honeypotPrefixes = append(idx.honeypotPrefixes, strings.TrimSuffix(v, "*"))
			} else {
				idx.honeypots[v] = true
			}
			continue
		case International:
			addPrefix(idx.intl, r.Value)
			continue
		case Exempt:
			switch r.Subject {
			case IP:
				addPrefix(idx.exemptIP, r.Value)
			case SPC:
				idx.exemptSPC[strings.ToUpper(r.Value)] = struct{}{}
			}
			continue
		}
		switch r.Subject {
		case Number:
			idx.numbers[strings.TrimPrefix(r.Value, "+")] = prefer(idx.numbers[strings.TrimPrefix(r.Value, "+")], r)
		case SPC:
			idx.spcs[strings.ToUpper(r.Value)] = prefer(idx.spcs[strings.ToUpper(r.Value)], r)
		case IP:
			p, err := netip.ParsePrefix(r.Value)
			if err != nil {
				continue
			}
			rows := idx.byLen[p.Bits()]
			if rows == nil {
				rows = map[netip.Prefix]Rule{}
				idx.byLen[p.Bits()] = rows
			}
			rows[p] = prefer(rows[p], r)
		}
	}
	return idx
}

func prefer(existing, candidate Rule) Rule {
	if existing.ID != 0 && existing.Kind == Deny {
		return existing
	}
	return candidate
}

// IsHoneypot reports whether a called number is listed as unassigned.
func (i *Index) IsHoneypot(number string) bool {
	if i == nil {
		return false
	}
	n := strings.TrimPrefix(normalizeNumber(number), "+")
	if n == "" {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.honeypots[n] {
		return true
	}
	for _, p := range i.honeypotPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// Count is the number of live rules indexed.
func (i *Index) Count() int {
	if i == nil {
		return 0
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.count
}

// Match returns the first matching rule, deny before allow, checking the
// number, the source IP, and the signer SPC.
func (i *Index) Match(number, sourceIP, spc string) (Hit, bool) {
	if i == nil {
		return Hit{}, false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	var allow *Rule
	consider := func(r Rule, ok bool) bool {
		if !ok {
			return false
		}
		if r.Kind == Deny {
			return true
		}
		if allow == nil {
			cp := r
			allow = &cp
		}
		return false
	}
	if n := strings.TrimPrefix(normalizeNumber(number), "+"); n != "" {
		if r, ok := i.numbers[n]; consider(r, ok) {
			return Hit{r}, true
		}
	}
	if spc != "" {
		if r, ok := i.spcs[strings.ToUpper(strings.TrimSpace(spc))]; consider(r, ok) {
			return Hit{r}, true
		}
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(sourceIP)); err == nil {
		addr = addr.Unmap()
		maxBits := 32
		if addr.Is6() {
			maxBits = 128
		}
		for bits := maxBits; bits >= 0; bits-- {
			rows := i.byLen[bits]
			if len(rows) == 0 {
				continue
			}
			p, err := addr.Prefix(bits)
			if err != nil {
				continue
			}
			if r, ok := rows[p]; consider(r, ok) {
				return Hit{r}, true
			}
		}
	}
	if allow != nil {
		return Hit{*allow}, true
	}
	return Hit{}, false
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// International reports whether the source address is an international peer.
func (i *Index) International(sourceIP string) bool {
	if i == nil {
		return false
	}
	addr, ok := parseIP(sourceIP)
	if !ok {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return prefixContains(i.intl, addr)
}

// Exempt reports whether the source address or the signer SPC skips the
// UK mobile caller ID check.
func (i *Index) Exempt(sourceIP, spc string) bool {
	if i == nil {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	if spc != "" {
		if _, ok := i.exemptSPC[strings.ToUpper(strings.TrimSpace(spc))]; ok {
			return true
		}
	}
	addr, ok := parseIP(sourceIP)
	if !ok {
		return false
	}
	return prefixContains(i.exemptIP, addr)
}

// PeerRules builds international and exempt rules from configuration text.
// Values are separated by commas or spaces. An empty string adds no rules.
func PeerRules(international, exemptPeers, exemptSPCs string) ([]Rule, error) {
	var out []Rule
	for _, raw := range splitList(international) {
		r, err := Normalize(Rule{Kind: International, Subject: IP, Value: raw, Origin: "config", Note: "international peer"})
		if err != nil {
			return nil, fmt.Errorf("international peer %q: %w", raw, err)
		}
		out = append(out, r)
	}
	for _, raw := range splitList(exemptPeers) {
		r, err := Normalize(Rule{Kind: Exempt, Subject: IP, Value: raw, Origin: "config", Note: "UK mobile exemption"})
		if err != nil {
			return nil, fmt.Errorf("exempt peer %q: %w", raw, err)
		}
		out = append(out, r)
	}
	for _, raw := range splitList(exemptSPCs) {
		r, err := Normalize(Rule{Kind: Exempt, Subject: SPC, Value: raw, Origin: "config", Note: "UK mobile exemption"})
		if err != nil {
			return nil, fmt.Errorf("exempt signer %q: %w", raw, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Merge appends rules that are not already present. Kind, subject, and
// value identify a rule.
func Merge(base, extra []Rule) []Rule {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]bool, len(base)+len(extra))
	out := make([]Rule, 0, len(base)+len(extra))
	for _, r := range base {
		seen[ruleKey(r)] = true
		out = append(out, r)
	}
	for _, r := range extra {
		if seen[ruleKey(r)] {
			continue
		}
		seen[ruleKey(r)] = true
		out = append(out, r)
	}
	return out
}

func ruleKey(r Rule) string {
	return string(r.Kind) + "\n" + string(r.Subject) + "\n" + r.Value
}

func splitList(s string) []string {
	return strings.Fields(strings.ReplaceAll(s, ",", " "))
}

func addPrefix(dst map[int]map[netip.Prefix]struct{}, value string) {
	p, err := netip.ParsePrefix(value)
	if err != nil {
		return
	}
	rows := dst[p.Bits()]
	if rows == nil {
		rows = map[netip.Prefix]struct{}{}
		dst[p.Bits()] = rows
	}
	rows[p] = struct{}{}
}

func prefixContains(byLen map[int]map[netip.Prefix]struct{}, addr netip.Addr) bool {
	if len(byLen) == 0 {
		return false
	}
	maxBits := 32
	if addr.Is6() {
		maxBits = 128
	}
	for bits := maxBits; bits >= 0; bits-- {
		rows := byLen[bits]
		if len(rows) == 0 {
			continue
		}
		p, err := addr.Prefix(bits)
		if err != nil {
			continue
		}
		if _, ok := rows[p]; ok {
			return true
		}
	}
	return false
}

func parseIP(source string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(source))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func normalizeNumber(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	if strings.HasPrefix(s, "+") {
		b.WriteByte('+')
	}
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "+" {
		return ""
	}
	if out != "" && !strings.HasPrefix(out, "+") {
		out = "+" + out
	}
	return out
}
