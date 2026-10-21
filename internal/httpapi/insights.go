package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/voice"
)

// Insight is one thing on the home screen that needs a decision. It
// carries the one action that settles it and a link to the evidence.
type Insight struct {
	Key      string         `json:"key"`
	Severity string         `json:"severity"`
	Title    string         `json:"title"`
	Detail   string         `json:"detail"`
	Action   *InsightAction `json:"action,omitempty"`
	Link     string         `json:"link,omitempty"`
	LinkText string         `json:"link_text,omitempty"`
}

// InsightAction is a rule to add or a setting to change.
type InsightAction struct {
	Label   string         `json:"label"`
	Rule    *RuleSpec      `json:"rule,omitempty"`
	Setting map[string]any `json:"setting,omitempty"`
}

// RuleSpec is the body POST /v1/rules takes.
type RuleSpec struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Value   string `json:"value"`
	Note    string `json:"note"`
}

const (
	sevCritical = "critical"
	sevWarning  = "warning"
	sevInfo     = "info"
	kvDismiss   = "insight_dismissed:"
)

func severityRank(s string) int {
	switch s {
	case sevCritical:
		return 0
	case sevWarning:
		return 1
	default:
		return 2
	}
}

// adder keeps an insight and reports whether it was kept.
type adder func(Insight) bool

// insights reads the window and lists what to act on, worst first. A
// subject a rule already covers is left out, and so is anything the
// operator dismissed. Two insights that propose the same rule keep the
// first, so producers run from the most specific to the most general.
func (s *Server) insights(ctx context.Context, from, to time.Time, ov Overview) []Insight {
	var out []Insight
	proposed := map[string]bool{}
	add := func(in Insight) bool {
		if s.dismissed(ctx, in.Key) {
			return false
		}
		if in.Action != nil && in.Action.Rule != nil {
			rule := in.Action.Rule.Subject + ":" + in.Action.Rule.Value
			if proposed[rule] {
				return false
			}
			proposed[rule] = true
		}
		out = append(out, in)
		return true
	}
	idx := s.ruleIndex()
	denied := func(subject lists.Subject, value string) bool {
		if idx == nil {
			return false
		}
		var hit lists.Hit
		var ok bool
		switch subject {
		case lists.Number:
			hit, ok = idx.Match(value, "", "")
		case lists.IP:
			hit, ok = idx.Match("", value, "")
		case lists.SPC:
			hit, ok = idx.Match("", "", value)
		}
		return ok && hit.Kind == lists.Deny
	}

	s.fccInsights(ctx, from, to, denied, add)
	s.spoofInsights(ctx, from, to, add)
	s.voiceInsights(ctx, from, to, denied, add)
	s.fasInsights(ctx, from, to, add)
	s.numberInsights(ctx, from, to, denied, add)
	s.signerInsights(ctx, from, to, denied, add)
	s.sourceInsights(ctx, from, to, denied, add)
	s.modeInsights(ov, add)
	s.healthInsights(ov, add)

	sort.SliceStable(out, func(i, j int) bool { return severityRank(out[i].Severity) < severityRank(out[j].Severity) })
	if len(out) > 8 {
		out = out[:8]
	}
	if out == nil {
		out = []Insight{}
	}
	return out
}

func (s *Server) spoofInsights(ctx context.Context, from, to time.Time, add adder) {
	evs, err := s.Store.Query(ctx, store.Filter{From: from, To: to, Q: "caller_id_not_owned", Direction: "outbound", Limit: 500})
	if err != nil {
		return
	}
	byCustomer := map[string]map[string]bool{}
	for _, ev := range evs {
		if ev.Customer == "" || !eventHasReason(ev, "caller_id_not_owned") {
			continue
		}
		if byCustomer[ev.Customer] == nil {
			byCustomer[ev.Customer] = map[string]bool{}
		}
		byCustomer[ev.Customer][ev.From] = true
	}
	for customer, numbers := range byCustomer {
		add(Insight{
			Key: "spoof:" + customer, Severity: sevCritical,
			Title:  fmt.Sprintf("Customer %s is spoofing caller IDs", customer),
			Detail: fmt.Sprintf("It sent %s it does not own. Falcon rejected them. Review the account before it gets a traceback.", plural(len(numbers), "caller ID")),
			Link:   "#calls?q=" + url.QueryEscape(customer), LinkText: "See the calls",
		})
	}
}

func (s *Server) voiceInsights(ctx context.Context, from, to time.Time, denied func(lists.Subject, string) bool, add adder) {
	samples, err := s.Store.VoiceSamplesSince(ctx, from, to, 500)
	if err != nil {
		return
	}
	count := map[string]int{}
	category := map[string]string{}
	for _, v := range samples {
		if v.From == "" || !voice.IsScamCategory(v.Category) || v.Score < liveScamThreshold {
			continue
		}
		count[v.From]++
		category[v.From] = v.Category
	}
	numbers := sortedByCount(count)
	for i, n := range numbers {
		if i == 3 {
			break
		}
		if denied(lists.Number, n) {
			continue
		}
		verb := "sound"
		if count[n] == 1 {
			verb = "sounds"
		}
		add(Insight{
			Key: "voice:" + n, Severity: sevCritical,
			Title:  fmt.Sprintf("Scam calls from %s", n),
			Detail: fmt.Sprintf("%s %s like a scam: %s.", plural(count[n], "recorded call"), verb, category[n]),
			Action: &InsightAction{Label: "Block number", Rule: &RuleSpec{Kind: "deny", Subject: "number", Value: n, Note: "scam calls recorded"}},
			Link:   "#calls?recorded=1&q=" + url.QueryEscape(n), LinkText: "Listen",
		})
	}
}

func (s *Server) fasInsights(ctx context.Context, from, to time.Time, add adder) {
	routes, err := s.Store.RouteStats(ctx, from, to)
	if err != nil {
		return
	}
	var bad []store.RouteStat
	total, secs := 0, 0.0
	for _, r := range routes {
		if r.FAS > 0 {
			bad = append(bad, r)
			total += r.FAS
			secs += r.FASSeconds
		}
	}
	if total == 0 {
		return
	}
	sort.SliceStable(bad, func(i, j int) bool { return bad[i].FAS > bad[j].FAS })
	names := make([]string, 0, len(bad))
	parts := make([]string, 0, len(bad))
	for _, r := range bad {
		name := r.Route
		if name == "" {
			name = "Calls without a vendor route"
		}
		names = append(names, name)
		parts = append(parts, fmt.Sprintf("%s %d", name, r.FAS))
	}
	in := Insight{
		Key: "fas:" + strings.Join(names, ","), Severity: sevWarning,
		Title:  fmt.Sprintf("%s: %s", names[0], plural(bad[0].FAS, "false answer")),
		Detail: fmt.Sprintf("%s of billed time was ringing, busy, or silence after the answer.", seconds(secs)),
		Link:   "#threats?tab=vendors", LinkText: "Compare vendors",
	}
	if len(bad) > 1 {
		in.Title = fmt.Sprintf("%s from %d vendors", plural(total, "false answer"), len(bad))
		in.Detail = strings.Join(parts, ", ") + ". " + in.Detail
	}
	if total >= 3 {
		in.Severity = sevCritical
	}
	if s.FASMode(ctx) == config.FASMonitor {
		in.Action = &InsightAction{Label: "Hold false answers", Setting: map[string]any{"fas_mode": config.FASEnforce}}
		in.Detail += " Falcon only watches now. Holding stops your customers paying for it."
	}
	add(in)
}

func (s *Server) numberInsights(ctx context.Context, from, to time.Time, denied func(lists.Subject, string) bool, add adder) {
	rows, err := s.Store.Suspects(ctx, from, to, "", 25)
	if err != nil {
		return
	}
	shown := 0
	for _, row := range rows {
		if shown == 3 {
			return
		}
		// Only flagged calls got through. A number Falcon rejects on every
		// call, or allows on every call, needs no rule.
		if row.Held == 0 || denied(lists.Number, row.Number) {
			continue
		}
		why := numberWhy(row)
		if why == "" {
			continue
		}
		them := "them"
		if row.Held == 1 {
			them = "it"
		}
		if add(Insight{
			Key: "number:" + row.Number, Severity: sevWarning,
			Title:  fmt.Sprintf("Block %s", row.Number),
			Detail: fmt.Sprintf("%s Falcon flagged %s and let %s through.", why, plural(row.Held, "call"), them),
			Action: &InsightAction{Label: "Block number", Rule: &RuleSpec{Kind: "deny", Subject: "number", Value: row.Number, Note: "from the overview"}},
			Link:   "#calls?q=" + url.QueryEscape(row.Number), LinkText: "See the calls",
		}) {
			shown++
		}
	}
}

// numberWhy is the behaviour that makes a number worth blocking, or "".
func numberWhy(row store.Suspect) string {
	reached := "It calls many different numbers."
	if row.Destinations >= 8 {
		reached = fmt.Sprintf("It called %d different numbers.", row.Destinations)
	}
	for _, hit := range row.Reasons {
		switch hit.Code {
		case "caller_fanout":
			return reached
		case "sequential_dialing":
			return "It dials numbers in sequence, like an autodialer."
		case "caller_hits_honeypots", "honeypot_target":
			return "It called your unassigned numbers."
		}
	}
	if row.Destinations >= 25 {
		return reached
	}
	return ""
}

func (s *Server) signerInsights(ctx context.Context, from, to time.Time, denied func(lists.Subject, string) bool, add adder) {
	parties, err := s.Store.Parties(ctx, "signer", from, to, 50)
	if err != nil {
		return
	}
	shown := 0
	for _, p := range parties {
		if shown == 2 || p.Total < 20 {
			continue
		}
		failed := pctOf(p.Failed, p.Total)
		rejected := pctOf(p.Reject, p.Total)
		if (failed < 30 && rejected < 50) || denied(lists.SPC, p.Name) {
			continue
		}
		label := p.Name
		if p.Label != "" {
			label = p.Name + " (" + p.Label + ")"
		}
		detail := fmt.Sprintf("%d%% of its %d calls failed STIR/SHAKEN verification.", failed, p.Total)
		if failed < 30 {
			detail = fmt.Sprintf("Falcon rejected %d%% of its %d calls.", rejected, p.Total)
		}
		if add(Insight{
			Key: "signer:" + p.Name, Severity: sevWarning,
			Title:  "Signer " + label + " sends bad calls",
			Detail: detail + " Blocking the signer stops every call it attests, whatever number it shows.",
			Action: &InsightAction{Label: "Block signer", Rule: &RuleSpec{Kind: "deny", Subject: "spc", Value: p.Name, Note: "from the overview"}},
			Link:   "#calls?q=" + url.QueryEscape(p.Name), LinkText: "See the calls",
		}) {
			shown++
		}
	}
}

func (s *Server) sourceInsights(ctx context.Context, from, to time.Time, denied func(lists.Subject, string) bool, add adder) {
	parties, err := s.Store.Parties(ctx, "ip", from, to, 50)
	if err != nil {
		return
	}
	shown := 0
	for _, p := range parties {
		if shown == 2 || p.Total < 20 || pctOf(p.Reject, p.Total) < 80 || denied(lists.IP, p.Name) {
			continue
		}
		if add(Insight{
			Key: "ip:" + p.Name, Severity: sevInfo,
			Title:  "Block " + p.Name + " at the edge",
			Detail: fmt.Sprintf("Falcon rejected %d of its %d calls. A block saves your switch the work.", p.Reject, p.Total),
			Action: &InsightAction{Label: "Block address", Rule: &RuleSpec{Kind: "deny", Subject: "ip", Value: p.Name, Note: "from the overview"}},
			Link:   "#calls?q=" + url.QueryEscape(p.Name), LinkText: "See the calls",
		}) {
			shown++
		}
	}
}

func (s *Server) modeInsights(ov Overview, add adder) {
	if ov.Status.Mode != config.ModeMonitor {
		return
	}
	detail := "Falcon records its decisions and lets every call through."
	if ov.Totals.Held > 0 {
		detail = fmt.Sprintf("%d calls would have been stopped in this window. Falcon let them through.", ov.Totals.Held)
	}
	add(Insight{
		Key: "mode:monitor", Severity: sevWarning, Title: "Monitor mode: nothing is blocked", Detail: detail,
		Action: &InsightAction{Label: "Start blocking", Setting: map[string]any{"mode": config.ModeEnforce}},
		Link:   "#calls?verdict=blocked", LinkText: "See what would stop",
	})
}

func (s *Server) healthInsights(ov Overview, add adder) {
	if ov.Totals.Screened == 0 && ov.Status.LastCallAt == nil {
		add(Insight{Key: "setup:connect", Severity: sevInfo, Title: "Connect your switch",
			Detail: "No calls yet. Point an adapter at POST /v1/screen, or add Falcon to your switch as a carrier and a customer.",
			Link:   "https://github.com/CallerAPI/Falcon#connect-a-switch", LinkText: "Setup guide"})
	} else if ov.Status.LastCallAt != nil && time.Since(*ov.Status.LastCallAt) > time.Hour && ov.Totals.Screened > 0 {
		add(Insight{Key: "health:quiet", Severity: sevWarning, Title: "No calls in the last hour",
			Detail: "The switch stopped asking Falcon. Check the adapter or the route to Falcon."})
	}
	if s.Trust != nil && s.Trust.Enabled() {
		if st := s.Trust.Status(); st.Roots == 0 {
			add(Insight{Key: "health:shaken", Severity: sevWarning, Title: "STIR/SHAKEN trust list is not loaded",
				Detail: "Signatures cannot be checked until the STI-PA list loads. Check outbound HTTPS from this host.", Link: "#settings", LinkText: "System"})
		}
	}
	if s.Feed != nil {
		if _, _, errText := s.Feed.Status(); errText != "" {
			add(Insight{Key: "health:feed", Severity: sevWarning, Title: "Spam list did not load", Detail: errText, Link: "#settings", LinkText: "System"})
		}
	}
	if s.Media != nil {
		if cap := s.Media.Capacity(); cap > 0 && s.Media.Active()*100/cap >= 80 {
			add(Insight{Key: "health:bridge", Severity: sevWarning, Title: "The bridge is near capacity",
				Detail: fmt.Sprintf("%d of %d bridged calls are up. Calls past the limit pass through unrecorded.", s.Media.Active(), cap)})
		}
	}
	if ov.Status.Update != "" {
		add(Insight{Key: "update:" + ov.Status.Update, Severity: sevInfo, Title: "Falcon " + ov.Status.Update + " is out",
			Detail: "You run " + ov.Status.Version + ".", Link: "https://github.com/CallerAPI/Falcon/releases", LinkText: "Release notes"})
	}
}

func (s *Server) dismissed(ctx context.Context, key string) bool {
	v, _ := s.Store.KVGet(ctx, kvDismiss+key)
	if v == "" {
		return false
	}
	until, err := strconv.ParseInt(v, 10, 64)
	return err == nil && time.Now().Unix() < until
}

func (s *Server) handleDismissInsight(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var body struct {
		Key   string `json:"key"`
		Hours int    `json:"hours"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil || strings.TrimSpace(body.Key) == "" || len(body.Key) > 200 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key required"})
		return
	}
	if body.Hours <= 0 || body.Hours > 24*90 {
		body.Hours = 24
	}
	until := time.Now().Add(time.Duration(body.Hours) * time.Hour).Unix()
	if err := s.Store.KVSet(r.Context(), kvDismiss+body.Key, strconv.FormatInt(until, 10)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "insight.dismiss", body.Key, fmt.Sprintf("%dh", body.Hours))
	writeJSON(w, http.StatusOK, map[string]any{"dismissed": body.Key, "until": until})
}

func eventHasReason(ev store.Event, code string) bool {
	for _, r := range ev.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

func sortedByCount(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func pctOf(a, b int) int {
	if b == 0 {
		return 0
	}
	return a * 100 / b
}

func seconds(s float64) string {
	switch {
	case s >= 3600:
		return fmt.Sprintf("%.1f hours", s/3600)
	case s >= 120:
		return fmt.Sprintf("%.0f minutes", s/60)
	default:
		return fmt.Sprintf("%.0f seconds", s)
	}
}
