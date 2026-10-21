// Package traceback answers traceback requests from the local call log. A
// request names a calling number, a called number, and a time. Falcon finds
// the call, names the upstream that sent it, and writes the answer. Under 47
// CFR 64.1200(n)(1) a provider must answer a traceback request from the
// registered traceback consortium within 24 hours.
package traceback

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

// Deadline is the time a provider has to answer.
const Deadline = 24 * time.Hour

// DefaultWindow is how far from the requested time a call may be. Switch
// clocks and request times are rarely the same second.
const DefaultWindow = 10 * time.Minute

// Variants are the forms a number can take in the call log. A North
// American number may be stored with or without the plus and the 1.
func Variants(number string) []string {
	var b strings.Builder
	for _, r := range number {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	d := b.String()
	switch {
	case d == "":
		return nil
	case len(d) == 10:
		return []string{d, "1" + d, "+1" + d}
	case len(d) == 11 && d[0] == '1':
		return []string{d[1:], d, "+" + d}
	default:
		return []string{d, "+" + d}
	}
}

// Pick returns the call nearest the requested time.
func Pick(events []store.Event, at time.Time) (store.Event, bool) {
	if len(events) == 0 {
		return store.Event{}, false
	}
	sorted := append([]store.Event(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return absDur(sorted[i].ReceivedAt.Sub(at)) < absDur(sorted[j].ReceivedAt.Sub(at))
	})
	return sorted[0], true
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// Found is what Falcon knows about the call a request names.
type Found struct {
	Event    *store.Event
	Upstream *store.Upstream
	// Standing is the upstream's FCC standing in words, when known.
	Standing string
	// RetentionDays bounds the search, for the answer when nothing matched.
	RetentionDays int
}

// Answer writes the reply a traceback request needs. It names who handed
// the call over and the evidence for it.
func Answer(c store.TracebackCase, f Found) string {
	var b strings.Builder
	ref := ""
	if c.Reference != "" {
		ref = " " + c.Reference
	}
	to := ""
	if c.To != "" {
		to = " to " + c.To
	}
	fmt.Fprintf(&b, "Traceback%s: call from %s%s at %s.\n", ref, c.From, to, utc(c.CallAt))
	if f.Event == nil {
		fmt.Fprintf(&b, "We have no record of this call within %s of that time. Our call records cover the last %d days.\n", window(c), f.RetentionDays)
		return b.String()
	}
	ev := f.Event
	if ev.Direction == "outbound" {
		who := "a customer"
		if ev.Customer != "" {
			who = "our customer " + ev.Customer
		}
		fmt.Fprintf(&b, "We originated this call for %s at %s.\n", who, utc(ev.ReceivedAt))
	} else if u := f.Upstream; u != nil {
		var parts []string
		if u.RMD != "" {
			parts = append(parts, u.RMD)
		}
		if u.FRN != "" {
			parts = append(parts, "FRN "+u.FRN)
		}
		ids := ""
		if len(parts) > 0 {
			ids = " (" + strings.Join(parts, ", ") + ")"
		}
		fmt.Fprintf(&b, "We received this call from %s%s at %s, from address %s.\n", u.Name, ids, utc(ev.ReceivedAt), orUnknown(ev.SourceIP))
		if u.Contact != "" {
			fmt.Fprintf(&b, "Upstream traceback contact: %s.\n", u.Contact)
		}
		if f.Standing != "" {
			fmt.Fprintf(&b, "FCC standing of the upstream: %s.\n", f.Standing)
		}
	} else {
		fmt.Fprintf(&b, "We received this call at %s from address %s. That address is not in our upstream registry.\n", utc(ev.ReceivedAt), orUnknown(ev.SourceIP))
	}
	if ev.CallID != "" {
		fmt.Fprintf(&b, "Call-ID: %s.\n", ev.CallID)
	}
	if ev.Attest != "" || ev.SignerSPC != "" {
		signer := strings.TrimSpace(ev.SignerSPC + " " + paren(ev.SignerName))
		fmt.Fprintf(&b, "STIR/SHAKEN: attestation %s, signed by %s, %s.\n", orUnknown(ev.Attest), orUnknown(signer), orUnknown(ev.Verstat))
	} else {
		b.WriteString("STIR/SHAKEN: the call was not signed.\n")
	}
	return b.String()
}

func window(c store.TracebackCase) string {
	return (time.Duration(c.WindowS) * time.Second).String()
}

func utc(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

func paren(s string) string {
	if s == "" {
		return ""
	}
	return "(" + s + ")"
}

// Row is one upstream in the monthly report. ID 0 is the traffic from
// addresses that no upstream owns.
type Row struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	RMD          string `json:"rmd,omitempty"`
	FRN          string `json:"frn,omitempty"`
	Standing     string `json:"standing,omitempty"`
	Confirmed    bool   `json:"confirmed,omitempty"`
	StandingText string `json:"standing_text,omitempty"`
	Calls        int    `json:"calls"`
	Blocked      int    `json:"blocked"`
	Flagged      int    `json:"flagged"`
	SpamHits     int    `json:"spam_hits"`
	Honeypots    int    `json:"honeypots"`
	VerifyFailed int    `json:"verify_failed"`
	Unsigned     int    `json:"unsigned"`
	Tracebacks   int    `json:"tracebacks"`
}

// Unregistered names the row for traffic no upstream owns.
const Unregistered = "Not in the registry"

// Standing is an upstream's FCC check as the report shows it.
type Standing struct {
	Code      string
	Confirmed bool
	Text      string
}

// Report adds the traffic of each source to the upstream that owns it, and
// counts each upstream's traceback cases. Every registered upstream gets a
// row, with or without traffic.
func Report(traffic []store.SourceTraffic, ups []store.Upstream, owner func(ip, spc string) (store.Upstream, bool), standing func(id int64) Standing, cases []store.TracebackCase) []Row {
	rows := map[int64]*Row{}
	for _, u := range ups {
		st := standing(u.ID)
		rows[u.ID] = &Row{ID: u.ID, Name: u.Name, RMD: u.RMD, FRN: u.FRN, Standing: st.Code, Confirmed: st.Confirmed, StandingText: st.Text}
	}
	get := func(ip, spc string) *Row {
		if u, ok := owner(ip, spc); ok {
			if r := rows[u.ID]; r != nil {
				return r
			}
		}
		if rows[0] == nil {
			rows[0] = &Row{Name: Unregistered}
		}
		return rows[0]
	}
	for _, t := range traffic {
		r := get(t.SourceIP, t.SPC)
		r.Calls += t.Calls
		r.Blocked += t.Blocked
		r.Flagged += t.Flagged
		r.SpamHits += t.SpamHits
		r.Honeypots += t.Honeypots
		r.VerifyFailed += t.VerifyFailed
		r.Unsigned += t.Unsigned
	}
	for _, c := range cases {
		if r := rows[c.UpstreamID]; r != nil && c.UpstreamID != 0 {
			r.Tracebacks++
		}
	}
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].ID == 0) != (out[j].ID == 0) {
			return out[j].ID == 0
		}
		if out[i].Blocked+out[i].Flagged != out[j].Blocked+out[j].Flagged {
			return out[i].Blocked+out[i].Flagged > out[j].Blocked+out[j].Flagged
		}
		return out[i].Name < out[j].Name
	})
	return out
}
