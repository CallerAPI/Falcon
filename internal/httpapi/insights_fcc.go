package httpapi

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/callerapi/falcon/internal/compliance"
	"github.com/callerapi/falcon/internal/lists"
)

// fccInsights puts the FCC standing of upstreams and signers on the home
// screen. An upstream under an order in monitor mode gets the one action
// that settles it: turn on enforcement.
func (s *Server) fccInsights(ctx context.Context, from, to time.Time, denied func(lists.Subject, string) bool, add adder) {
	if s.Compliance == nil {
		return
	}
	ups, err := s.Store.Upstreams(ctx)
	if err != nil {
		return
	}
	enforce := s.FCCMode(ctx) == compliance.ModeEnforce
	unchecked := 0
	for _, u := range ups {
		r, ok := s.Compliance.Result(u.ID)
		if !ok {
			continue
		}
		id := strconv.FormatInt(u.ID, 10)
		switch {
		case r.Blocks() && !enforce:
			add(Insight{
				Key: "fcc:" + id + ":" + r.Standing, Severity: sevCritical,
				Title:  fmt.Sprintf("Upstream %s is %s", u.Name, compliance.Words(r)),
				Detail: compliance.Describe(u, r) + " The FCC autopilot is in monitor mode, so its calls still pass.",
				Action: &InsightAction{Label: "Block upstreams under FCC orders", Setting: map[string]any{"fcc_mode": compliance.ModeEnforce}},
				Link:   "#rules", LinkText: "See upstreams",
			})
		case r.Blocks() && len(u.IPs)+len(u.SPCs) == 0:
			add(Insight{
				Key: "fcc-norules:" + id, Severity: sevCritical,
				Title:  fmt.Sprintf("Falcon can not block upstream %s", u.Name),
				Detail: compliance.Describe(u, r) + " The upstream has no addresses or signer codes. Add them in Rules.",
				Link:   "#rules", LinkText: "Add addresses",
			})
		case !r.Confirmed && compliance.Bad(r.Standing):
			add(Insight{
				Key: "fcc-maybe:" + id + ":" + r.Standing, Severity: sevWarning,
				Title:  fmt.Sprintf("Upstream %s may be under an FCC order", u.Name),
				Detail: compliance.Describe(u, r) + " Falcon matched the name only and does not block on a name. Add the RMD number or FRN to confirm.",
				Link:   "#rules", LinkText: "Add the RMD number",
			})
		case r.Standing == compliance.NotFound:
			add(Insight{
				Key: "fcc-notfound:" + id, Severity: sevWarning,
				Title:  fmt.Sprintf("Upstream %s is not in the Robocall Mitigation Database", u.Name),
				Detail: compliance.Describe(u, r) + " A provider that never filed may not send you calls directly.",
				Link:   "#rules", LinkText: "Check the number",
			})
		case r.Standing == compliance.Unknown:
			unchecked++
		}
	}
	if unchecked > 0 {
		add(Insight{
			Key: "fcc-unchecked", Severity: sevInfo,
			Title:  fmt.Sprintf("%s with no RMD number", plural(unchecked, "upstream")),
			Detail: "Falcon can not check them against FCC orders. Add the RMD number or FRN of each one.",
			Link:   "#rules", LinkText: "Add RMD numbers",
		})
	}
	s.fccSignerInsights(ctx, from, to, denied, add)
}

// fccSignerInsights names signers under an FCC order. A signer is matched
// by the company name on its certificate, and it may not be the upstream,
// so the action is a signer rule the operator chooses.
func (s *Server) fccSignerInsights(ctx context.Context, from, to time.Time, denied func(lists.Subject, string) bool, add adder) {
	parties, err := s.Store.Parties(ctx, "signer", from, to, 50)
	if err != nil {
		return
	}
	for _, p := range parties {
		if p.Name == "" || p.Label == "" || denied(lists.SPC, p.Name) {
			continue
		}
		r, ok := s.Compliance.Signer(p.Label)
		if !ok || (r.Standing != compliance.Blocked && r.Standing != compliance.Removed) {
			continue
		}
		add(Insight{
			Key: "fcc-signer:" + p.Name, Severity: sevWarning,
			Title:  fmt.Sprintf("Calls signed by %s, %s", p.Label, compliance.Words(r)),
			Detail: fmt.Sprintf("%s in this window carried its signature (SPC %s). Falcon matched the certificate name, not an RMD number.", plural(p.Total, "call"), p.Name),
			Action: &InsightAction{Label: "Block signer", Rule: &RuleSpec{Kind: "deny", Subject: "spc", Value: p.Name, Note: "signer " + compliance.Words(r)}},
			Link:   "#calls?q=" + url.QueryEscape(p.Name), LinkText: "See the calls",
		})
	}
}
