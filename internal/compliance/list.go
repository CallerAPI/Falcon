// Package compliance is the FCC autopilot. It checks the operator's upstream
// carriers against the FCC standing of every provider: the Robocall
// Mitigation Database (RMD), FCC removal orders, and final determination
// orders. CallerAPI serves the whole list. Matching runs on this host, so
// CallerAPI never learns who the operator takes traffic from.
//
//   - 47 CFR 64.6305(g): a provider may accept calls directly only from a
//     provider whose filing is in the RMD.
//   - 47 CFR 64.1200(n)(3): a final determination order makes downstream
//     providers block traffic from the provider it names.
package compliance

import (
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

// Order kinds on the wire.
const (
	OrderBlock   = "block"
	OrderRemoval = "removal"
)

// Standing of an upstream.
const (
	// Listed: in the RMD with no FCC order.
	Listed = "listed"
	// Unlisted: no longer in the RMD and no order names it.
	Unlisted = "unlisted"
	// Removed: an FCC order removed it from the RMD.
	Removed = "removed"
	// Blocked: a final determination order names it.
	Blocked = "blocked"
	// NotFound: the RMD number or FRN the operator entered is not in the list.
	NotFound = "not_found"
	// Unknown: no RMD number or FRN, and no provider has the same name.
	Unknown = "unknown"
)

// Bad reports whether a standing means its calls may not be accepted
// directly.
func Bad(standing string) bool {
	return standing == Blocked || standing == Removed || standing == Unlisted
}

// Provider is one row of the CallerAPI list.
type Provider struct {
	RMD          string     `json:"rmd,omitempty"`
	FRN          string     `json:"frn,omitempty"`
	Name         string     `json:"name"`
	DBA          string     `json:"dba,omitempty"`
	Listed       bool       `json:"listed"`
	DelistedAt   *time.Time `json:"delisted_at,omitempty"`
	Order        string     `json:"order,omitempty"`
	OrderDoc     string     `json:"order_doc,omitempty"`
	OrderDate    string     `json:"order_date,omitempty"`
	Tracebacks   int        `json:"tracebacks,omitempty"`
	NonResponses int        `json:"non_responses,omitempty"`
}

// List is the wire format of GET /api/falcon/v1/enforcement.
type List struct {
	GeneratedAt time.Time  `json:"generated_at"`
	Providers   []Provider `json:"providers"`
}

// Standing is what the list says about one provider, and since when.
func (p Provider) Standing() (string, string) {
	switch {
	case p.Order == OrderBlock:
		return Blocked, p.OrderDate
	case p.Order == OrderRemoval && !p.Listed:
		return Removed, p.OrderDate
	case !p.Listed:
		since := ""
		if p.DelistedAt != nil {
			since = p.DelistedAt.UTC().Format("2006-01-02")
		}
		return Unlisted, since
	default:
		return Listed, ""
	}
}

// Result is the check of one upstream. Confirmed means the RMD number or FRN
// matched. A name match alone is never confirmed and never blocks.
type Result struct {
	UpstreamID int64     `json:"upstream_id"`
	Standing   string    `json:"standing"`
	Confirmed  bool      `json:"confirmed"`
	Since      string    `json:"since,omitempty"`
	Provider   *Provider `json:"provider,omitempty"`
	Candidates int       `json:"candidates,omitempty"`
}

// Blocks reports whether the autopilot may block the upstream.
func (r Result) Blocks() bool { return r.Confirmed && Bad(r.Standing) }

// Index answers checks against one list.
type Index struct {
	generatedAt time.Time
	count       int
	byRMD       map[string]*Provider
	byFRN       map[string][]*Provider
	byName      map[string][]*Provider
}

// NewIndex builds an index. A provider is found by its RMD number, its FRN,
// its name, and each DBA name.
func NewIndex(l List) *Index {
	ix := &Index{generatedAt: l.GeneratedAt, count: len(l.Providers), byRMD: map[string]*Provider{}, byFRN: map[string][]*Provider{}, byName: map[string][]*Provider{}}
	for i := range l.Providers {
		p := &l.Providers[i]
		if rmd := NormalizeRMD(p.RMD); rmd != "" {
			ix.byRMD[rmd] = p
		}
		if frn := NormalizeFRN(p.FRN); frn != "" {
			ix.byFRN[frn] = append(ix.byFRN[frn], p)
		}
		seen := map[string]bool{}
		for _, n := range append([]string{p.Name}, strings.Split(p.DBA, ";")...) {
			if key := NormalizeName(n); key != "" && !seen[key] {
				seen[key] = true
				ix.byName[key] = append(ix.byName[key], p)
			}
		}
	}
	return ix
}

// Count is the number of providers in the list.
func (ix *Index) Count() int { return ix.count }

// GeneratedAt is when CallerAPI built the list.
func (ix *Index) GeneratedAt() time.Time { return ix.generatedAt }

// Check finds an upstream's standing. The RMD number wins over the FRN, and
// the FRN over the name.
func (ix *Index) Check(u store.Upstream) Result {
	out := Result{UpstreamID: u.ID}
	if rmd := NormalizeRMD(u.RMD); rmd != "" {
		p, ok := ix.byRMD[rmd]
		if !ok {
			out.Standing = NotFound
			return out
		}
		return fill(out, []*Provider{p}, true)
	}
	if frn := NormalizeFRN(u.FRN); frn != "" {
		ps := ix.byFRN[frn]
		if len(ps) == 0 {
			out.Standing = NotFound
			return out
		}
		return fill(out, ps, true)
	}
	ps := ix.byName[NormalizeName(u.Name)]
	if len(ps) == 0 {
		out.Standing = Unknown
		return out
	}
	out = fill(out, ps, false)
	out.Candidates = len(ps)
	return out
}

// ByName returns the worst standing among providers with this name. It is
// for signer certificates, which carry a company name and no RMD number.
func (ix *Index) ByName(name string) (Result, bool) {
	ps := ix.byName[NormalizeName(name)]
	if len(ps) == 0 {
		return Result{}, false
	}
	r := fill(Result{}, ps, false)
	r.Candidates = len(ps)
	return r, true
}

var rank = map[string]int{Blocked: 4, Removed: 3, Unlisted: 2, Listed: 1}

// fill picks the worst standing of a group of filings. A filing that is no
// longer listed does not count while another filing in the group is listed,
// because a company can refile under a new RMD number. A group with an order
// on one filing and a clean listing on another is not confirmed: the
// operator must enter the RMD number before the autopilot blocks.
func fill(out Result, ps []*Provider, confirmed bool) Result {
	anyListed := false
	for _, p := range ps {
		anyListed = anyListed || p.Listed
	}
	best, clean, bad := -1, 0, 0
	for _, p := range ps {
		st, since := p.Standing()
		if st == Unlisted && anyListed {
			continue
		}
		if st == Listed {
			clean++
		} else {
			bad++
		}
		if rank[st] > best {
			best = rank[st]
			out.Standing, out.Since, out.Provider = st, since, p
		}
	}
	out.Confirmed = confirmed && !(clean > 0 && bad > 0)
	return out
}

// NormalizeRMD returns RMD followed by seven digits, or "".
func NormalizeRMD(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	digits := strings.TrimPrefix(s, "RMD")
	if len(digits) == 0 || len(digits) > 7 || !allDigits(digits) {
		return ""
	}
	return "RMD" + strings.Repeat("0", 7-len(digits)) + digits
}

// NormalizeFRN returns the ten digit FRN, or "".
func NormalizeFRN(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	d := b.String()
	if d == "" || len(d) > 10 {
		return ""
	}
	return strings.Repeat("0", 10-len(d)) + d
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

var corporateWords = map[string]bool{
	"llc": true, "inc": true, "incorporated": true, "corp": true, "corporation": true, "co": true,
	"company": true, "ltd": true, "limited": true, "lp": true, "llp": true, "plc": true, "the": true, "dba": true,
}

// NormalizeName folds a company name for matching: lower case, dots dropped
// so that L.L.C. reads as LLC, other punctuation removed, and corporate
// words such as LLC or Inc. dropped. Both sides of every match go through
// it on this host.
func NormalizeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.ReplaceAll(s, ".", "")) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune(' ')
		}
	}
	var words []string
	for _, w := range strings.Fields(b.String()) {
		if !corporateWords[w] {
			words = append(words, w)
		}
	}
	return strings.Join(words, " ")
}
