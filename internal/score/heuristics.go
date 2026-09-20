package score

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/sipmsg"
	"github.com/callerapi/falcon/internal/velocity"
)

// Enrichment is optional signal input from outside the SIP message.
type Enrichment struct {
	FeedEnabled  bool
	FeedHit      bool
	FirewallOn   bool
	FirewallSpam bool
	FeedURL      string
	FirewallURL  string

	// IP is the telecom IP intel row for the source address, when the table
	// has one. Provider is shown on every event; Risk moves the score.
	IP *IPIntel
	// Shaken is the verification outcome when the verifier ran.
	Shaken *Shaken
	// List is the operator's own allow or deny rule when one matched.
	List *ListHit
	// Network is what every sharing install has seen of this signer and
	// this sending tool. Nil when the feed is off or has no row.
	Network *Network
	// Direction is "outbound" when the operator's own customer is calling
	// out. Everything else is inbound.
	Direction string
	// Customer is the operator's account behind an outbound call, when the
	// adapter named one and Falcon knows it.
	Customer *CustomerCtx
	// Caller is what this calling number did in the last hour on this
	// install: volume, fan-out, answer rate, talk time, dialing pattern.
	Caller *Behaviour
	// Honeypot marks a call to a number the operator listed as unassigned.
	// Nobody legitimate dials an unassigned number.
	Honeypot bool
}

// CustomerCtx is the operator's own account and whether it may present
// the calling number.
type CustomerCtx struct {
	ID         string
	Known      bool
	OwnsCaller bool
	HasDIDs    bool
}

// Behaviour is the calling number's recent activity, precomputed by the
// caller from the store.
type Behaviour struct {
	Calls           int
	DistinctCallees int
	Completed       int
	Answered        int
	TalkSeconds     int
	Sequential      bool
	HoneypotHits    int
}

// ASR is the answer rate in percent over calls with a known outcome.
func (b Behaviour) ASR() int {
	if b.Completed == 0 {
		return 0
	}
	return b.Answered * 100 / b.Completed
}

// ACD is average talk time over answered calls, in seconds.
func (b Behaviour) ACD() int {
	if b.Answered == 0 {
		return 0
	}
	return b.TalkSeconds / b.Answered
}

// Network carries the CallerAPI feed scores. Installs is the number of
// independent installs behind each score; a score from one install is
// an opinion, from five it is a pattern.
type Network struct {
	SignerScore         int
	SignerInstalls      int
	FingerprintScore    int
	FingerprintInstalls int
	// Enforce lets a strong signer score reject on its own.
	Enforce bool
}

// IPIntel is the source-address verdict from the CIDR table.
type IPIntel struct {
	Provider string
	Risk     string
	Tags     []string
}

// Shaken is what the scorer needs from a PASSporT verification.
type Shaken struct {
	Verstat    string
	Pending    bool
	Revoked    bool
	SignerSPC  string
	SignerName string
	Errors     []string
}

// ListHit is a matched operator rule.
type ListHit struct {
	Kind    string
	Subject string
	Value   string
	Note    string
	RuleID  int64
}

// Limits are velocity trip points.
type Limits struct {
	Window time.Duration
	IP     int
	From   int
	Scan   int
	// Behaviour thresholds over the last hour. Zero disables a rule.
	Fanout       int // distinct callees from one number
	SequentialN  int // consecutive +1 callees that mean a dialer
	LowASRCalls  int // completed calls before ASR counts
	LowASRPct    int // answer rate at or below which it is suspicious
	ShortCalls   int // answered calls before ACD counts
	ShortSeconds int // average talk time at or below which it is suspicious
}

// DefaultBehaviour are the behaviour thresholds when none are set.
func DefaultBehaviour(l Limits) Limits {
	if l.Fanout == 0 {
		l.Fanout = 30
	}
	if l.SequentialN == 0 {
		l.SequentialN = 5
	}
	if l.LowASRCalls == 0 {
		l.LowASRCalls = 20
	}
	if l.LowASRPct == 0 {
		l.LowASRPct = 20
	}
	if l.ShortCalls == 0 {
		l.ShortCalls = 10
	}
	if l.ShortSeconds == 0 {
		l.ShortSeconds = 12
	}
	return l
}

// Engine scores a SIP snapshot.
type Engine struct {
	Thresh Thresholds
	Limits Limits
	Vel    *velocity.Window
	Now    func() time.Time
}

func NewEngine(t Thresholds, lim Limits) *Engine {
	return &Engine{
		Thresh: t,
		Limits: lim,
		Vel:    velocity.New(lim.Window),
		Now:    time.Now,
	}
}

func (e *Engine) Score(s sipmsg.Snapshot, en Enrichment) Result {
	var reasons []Reason
	add := func(code, category, detail string, weight int) {
		if weight <= 0 {
			return
		}
		reasons = append(reasons, Reason{Code: code, Weight: weight, Detail: detail, Category: category})
	}

	from := s.FromUser
	to := s.ToUser
	ua := strings.ToLower(s.UserAgent)

	// An operator allow rule ends scoring. Nothing else is read.
	if en.List != nil && en.List.Kind == "allow" {
		reasons = append(reasons, Reason{
			Code: "allowlist_" + en.List.Subject, Weight: 0, Category: "list",
			Detail: fmt.Sprintf("Operator allow rule #%d matches %s %s", en.List.RuleID, en.List.Subject, en.List.Value),
		})
		return e.finish(s, en, reasons, 0, ActionAllow, "allowlist")
	}

	if isScannerUA(ua) {
		add("scanner_user_agent", "ua", "User-Agent matches a known SIP scanner", 90)
	}
	if strings.TrimSpace(s.UserAgent) == "" {
		add("missing_user_agent", "ua", "User-Agent header is missing", 10)
	}

	if strings.TrimSpace(s.FromRaw) == "" {
		add("missing_from", "identity", "From header is missing", 40)
	}
	if isAnonymous(from) && s.PAIUser == "" {
		add("anonymous_from_no_pai", "identity", "Anonymous From without P-Asserted-Identity", 25)
	}
	if numbersDiffer(from, s.PAIUser) {
		add("from_pai_mismatch", "identity", "From user does not match P-Asserted-Identity", 35)
	}
	if numbersDiffer(from, s.RPIDUser) {
		add("from_rpid_mismatch", "identity", "From user does not match Remote-Party-ID", 20)
	}
	if hasPrivacyID(s.Privacy) && !isAnonymous(from) && s.PAIUser != "" && numbersDiffer(from, s.PAIUser) {
		add("privacy_id_spoof", "identity", "Privacy id with a From that does not match PAI", 25)
	}

	if s.Identity.Raw == "" {
		add("missing_identity", "shaken", "Identity header is missing (no STIR/SHAKEN)", 15)
	} else if !s.Identity.ValidJWT {
		add("shaken_invalid", "shaken", "Identity header is not a readable PASSporT JWT", 30)
	} else {
		switch s.Identity.Attest {
		case "C":
			add("shaken_attest_c", "shaken", "STIR/SHAKEN attestation C (gateway)", 20)
		case "B":
			add("shaken_attest_b", "shaken", "STIR/SHAKEN attestation B (partial)", 8)
		}
		if s.Identity.OrigTN != "" && numeric(from) && numbersDiffer(from, s.Identity.OrigTN) {
			add("shaken_orig_mismatch", "shaken", "PASSporT orig tn does not match From", 40)
		}
		if s.Identity.IAT > 0 {
			now := e.Now().Unix()
			if s.Identity.IAT > now+120 {
				add("shaken_iat_future", "shaken", "PASSporT iat is in the future", 20)
			} else if now-s.Identity.IAT > 90 {
				add("shaken_iat_stale", "shaken", "PASSporT iat is older than 90 seconds", 15)
			}
		}
	}

	if s.ViaHops >= 8 {
		add("via_hop_flood", "routing", fmt.Sprintf("Via chain has %d hops", s.ViaHops), 25)
	}
	if s.ContactHost != "" && s.SourceIP != "" && isPrivateHost(s.ContactHost) && !isPrivateHost(s.SourceIP) {
		add("contact_private_src_public", "routing", "Contact host is private while the source IP is public", 20)
	}

	if s.CallID == "" {
		add("missing_call_id", "hygiene", "Call-ID header is missing", 20)
	}
	if s.MaxForwards >= 0 && s.MaxForwards < 10 {
		add("max_forwards_low", "hygiene", fmt.Sprintf("Max-Forwards is %d", s.MaxForwards), 15)
	}

	if numeric(from) && !plausibleE164(from) {
		add("invalid_from_number", "number", "From user is not a plausible E.164 number", 15)
	}
	if numeric(to) && isPremiumRate(to) {
		add("premium_rate_dest", "fraud", "Destination looks like a premium-rate number", 35)
	}
	if numeric(from) && numeric(to) && sameNumber(from, to) {
		add("from_equals_to", "number", "From and To are the same number", 10)
	}
	if numeric(from) && (isRepeatingDigits(from) || isSequentialDigits(from)) {
		add("synthetic_from", "number", "From number is sequential or repeating digits", 20)
	}

	if strings.EqualFold(s.Method, "INVITE") && !s.HasSDP {
		add("invite_no_sdp", "sdp", "INVITE has no SDP body", 5)
	}
	if s.SDPZero {
		add("sdp_zero_connection", "sdp", "SDP connection address is 0.0.0.0 or ::", 15)
	}

	now := e.Now()
	if e.Vel != nil && s.SourceIP != "" {
		if n := e.Vel.Hit("ip:"+s.SourceIP, now); e.Limits.IP > 0 && n > e.Limits.IP {
			add("source_invite_flood", "velocity", fmt.Sprintf("%d requests from this source IP in the window", n), 40)
		}
		if to != "" {
			if n := e.Vel.Unique("scan:"+s.SourceIP, to, now); e.Limits.Scan > 0 && n > e.Limits.Scan {
				add("source_dest_scan", "velocity", fmt.Sprintf("%d distinct destinations from this source IP", n), 45)
			}
		}
	}
	if e.Vel != nil && numeric(from) {
		if n := e.Vel.Hit("from:"+from, now); e.Limits.From > 0 && n > e.Limits.From {
			add("from_invite_flood", "velocity", fmt.Sprintf("%d requests from this From in the window", n), 30)
		}
	}

	if en.Shaken != nil && s.Identity.Raw != "" {
		switch {
		case en.Shaken.Revoked:
			add("shaken_cert_revoked", "shaken", "Signing certificate is on the STI-PA revocation list", 60)
		case en.Shaken.Verstat == "TN-Validation-Failed":
			add("shaken_verify_failed", "shaken", "PASSporT failed verification: "+strings.Join(en.Shaken.Errors, "; "), 45)
		case en.Shaken.Pending:
			// Cold cache. Nothing is known yet, so nothing is charged.
		case en.Shaken.Verstat == "No-TN-Validation" && len(en.Shaken.Errors) > 0:
			add("shaken_unverifiable", "shaken", "PASSporT could not be verified: "+strings.Join(en.Shaken.Errors, "; "), 10)
		}
	}

	hardBlock := false
	blockSource := ""
	if en.List != nil && en.List.Kind == "deny" {
		add("denylist_"+en.List.Subject, "list", fmt.Sprintf("Operator deny rule #%d matches %s %s", en.List.RuleID, en.List.Subject, en.List.Value), 100)
		hardBlock = true
		blockSource = "denylist"
	}
	if en.FeedHit {
		add("spam_feed_hit", "feed", "Calling number is on the CallerAPI spam feed", 100)
		hardBlock = true
		if blockSource == "" {
			blockSource = "spam_feed"
		}
	}
	if en.FirewallSpam {
		add("voice_firewall_spam", "firewall", "Voice firewall marked this caller as spam", 55)
	}
	if en.IP != nil {
		who := en.IP.Provider
		if who == "" {
			who = "an unnamed provider"
		}
		switch en.IP.Risk {
		case "block":
			add("ip_intel_block", "ipintel", fmt.Sprintf("Source IP belongs to %s, listed as block", who), 100)
			hardBlock = true
			if blockSource == "" {
				blockSource = "ip_intel"
			}
		case "hostile":
			add("ip_intel_hostile", "ipintel", fmt.Sprintf("Source IP belongs to %s, listed as hostile", who), 60)
		case "suspicious":
			add("ip_intel_suspicious", "ipintel", fmt.Sprintf("Source IP belongs to %s, listed as suspicious", who), 30)
		}
	}

	// Outbound: the operator's own customer is calling. A caller id the
	// customer does not own is spoofing, and spoofing from your own
	// platform is what regulators fine. Nothing else in the message can
	// argue with it.
	if en.Direction == "outbound" && en.Customer != nil && en.Customer.Known && en.Customer.HasDIDs && !en.Customer.OwnsCaller {
		add("caller_id_not_owned", "outbound", fmt.Sprintf("Customer %s presented %s, which is not in its number list", en.Customer.ID, from), 100)
		hardBlock = true
		if blockSource == "" {
			blockSource = "caller_id"
		}
	}
	if en.Honeypot {
		add("honeypot_target", "behaviour", fmt.Sprintf("Called number %s is listed as unassigned; nobody legitimate dials it", to), 70)
	}
	if b := en.Caller; b != nil {
		lim := DefaultBehaviour(e.Limits)
		if b.DistinctCallees >= lim.Fanout {
			add("caller_fanout", "behaviour", fmt.Sprintf("%s reached %d different numbers in the last hour", from, b.DistinctCallees), 40)
		}
		if b.Sequential {
			add("sequential_dialing", "behaviour", fmt.Sprintf("%s is dialing consecutive numbers", from), 45)
		}
		if b.Completed >= lim.LowASRCalls && b.ASR() <= lim.LowASRPct {
			add("caller_low_asr", "behaviour", fmt.Sprintf("%d%% of %s's last %d calls were answered", b.ASR(), from, b.Completed), 30)
		}
		if b.Answered >= lim.ShortCalls && b.ACD() <= lim.ShortSeconds {
			add("caller_short_calls", "behaviour", fmt.Sprintf("%s's answered calls last %d seconds on average", from, b.ACD()), 30)
		}
		if b.HoneypotHits >= 2 {
			add("caller_hits_honeypots", "behaviour", fmt.Sprintf("%s dialed %d unassigned numbers in the last hour", from, b.HoneypotHits), 60)
		}
	}

	if n := en.Network; n != nil {
		// Reputation is corroboration, not proof. Alone it reaches
		// challenge at most, unless the operator turned on enforce.
		if n.SignerInstalls >= 3 && n.SignerScore >= 70 {
			w := n.SignerScore / 2
			if w > 45 {
				w = 45
			}
			if n.Enforce && n.SignerScore >= 90 && n.SignerInstalls >= 5 {
				w = 100
				hardBlock = true
				if blockSource == "" {
					blockSource = "network_signer"
				}
			}
			add("network_signer", "network", fmt.Sprintf("Signer scores %d across %d installs on the CallerAPI network", n.SignerScore, n.SignerInstalls), w)
		}
		if n.FingerprintInstalls >= 3 && n.FingerprintScore >= 70 {
			w := n.FingerprintScore / 3
			if w > 30 {
				w = 30
			}
			add("network_fingerprint", "network", fmt.Sprintf("Sending tool scores %d across %d installs on the CallerAPI network", n.FingerprintScore, n.FingerprintInstalls), w)
		}
	}

	total := 0
	for _, r := range reasons {
		total += r.Weight
	}
	if total > 100 {
		total = 100
	}

	action := e.Thresh.Action(total)
	if hardBlock {
		total = 100
		action = ActionReject
	}
	return e.finish(s, en, reasons, total, action, blockSource)
}

// finish assembles the Result. blockSource names the hard block, or is
// "allowlist" for an operator allow, or empty.
func (e *Engine) finish(s sipmsg.Snapshot, en Enrichment, reasons []Reason, total int, action Action, blockSource string) Result {
	status, reason := action.SIP()
	headers := map[string]string{
		"X-Falcon-Score":   fmt.Sprintf("%d", total),
		"X-Falcon-Action":  string(action),
		"X-Falcon-Reasons": reasonCodes(reasons),
	}
	if action == ActionReject && blockSource != "" {
		headers["X-Falcon-Block"] = blockSource
	}
	sig := Signals{
		Method:       s.Method,
		From:         s.FromUser,
		To:           s.ToUser,
		CallID:       s.CallID,
		UserAgent:    s.UserAgent,
		SourceIP:     s.SourceIP,
		ShakenAttest: s.Identity.Attest,
		ShakenOrigID: s.Identity.OrigID,
		ViaHops:      s.ViaHops,
		FeedHit:      en.FeedHit,
		FirewallSpam: en.FirewallSpam,
		FeedEnabled:  en.FeedEnabled,
		FirewallOn:   en.FirewallOn,
	}
	if en.Network != nil {
		sig.NetworkSignerScore = en.Network.SignerScore
		sig.NetworkFingerprintScore = en.Network.FingerprintScore
	}
	sig.Direction = en.Direction
	if en.Customer != nil {
		sig.Customer = en.Customer.ID
	}
	sig.Honeypot = en.Honeypot
	if en.Caller != nil {
		sig.CallerCalls = en.Caller.Calls
		sig.CallerDistinctCallees = en.Caller.DistinctCallees
		sig.CallerASR = en.Caller.ASR()
		sig.CallerACD = en.Caller.ACD()
		sig.CallerSequential = en.Caller.Sequential
	}
	if en.IP != nil {
		sig.IPProvider = en.IP.Provider
		sig.IPRisk = en.IP.Risk
		sig.IPTags = en.IP.Tags
		if en.IP.Provider != "" {
			headers["X-Falcon-Provider"] = en.IP.Provider
		}
	}
	if en.Shaken != nil {
		sig.Verstat = en.Shaken.Verstat
		sig.SignerSPC = en.Shaken.SignerSPC
		sig.SignerName = en.Shaken.SignerName
		if sig.Verstat != "" {
			headers["X-Falcon-Verstat"] = sig.Verstat
		}
		if sig.SignerSPC != "" {
			headers["X-Falcon-Signer"] = sig.SignerSPC
		}
	}
	if en.List != nil {
		sig.ListRule = en.List.RuleID
		sig.ListKind = en.List.Kind
	}

	return Result{
		Action:      action,
		RiskScore:   total,
		RiskBand:    action.Band(),
		SIPStatus:   status,
		SIPReason:   reason,
		Reasons:     reasons,
		Signals:     sig,
		Headers:     headers,
		SwitchHints: action.Hints(),
		Upsell:      buildUpsell(en),
	}
}

func buildUpsell(en Enrichment) Upsell {
	return Upsell{
		SpamFeed: AddOn{
			Available: true,
			Connected: en.FeedEnabled,
			URL:       en.FeedURL,
			Headline:  "Spam database feed",
			Detail:    "Load the CallerAPI spam snapshot onto this switch. A listed From is a hard reject.",
		},
		VoiceFirewall: AddOn{
			Available: true,
			Connected: en.FirewallOn,
			URL:       en.FirewallURL,
			Headline:  "Voice firewall",
			Detail:    "Screen each INVITE against live reputation, or send signaling through the hosted SIP firewall.",
		},
	}
}

func reasonCodes(reasons []Reason) string {
	if len(reasons) == 0 {
		return ""
	}
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		parts = append(parts, r.Code)
	}
	return strings.Join(parts, ",")
}

func isScannerUA(ua string) bool {
	if ua == "" {
		return false
	}
	needles := []string{
		"friendly-scanner",
		"sipvicious",
		"sundayddr",
		"sip-scan",
		"sipcli",
		"vaxsipuseragent",
		"pplsip",
		"sip-informant",
		"golddigger",
		"siparmyknife",
		"iwar",
		"sipsak",
	}
	for _, n := range needles {
		if strings.Contains(ua, n) {
			return true
		}
	}
	return false
}

func isAnonymous(user string) bool {
	switch strings.ToLower(user) {
	case "", "anonymous", "unavailable", "restricted", "unknown", "anonymous.invalid":
		return true
	default:
		return false
	}
}

func hasPrivacyID(p string) bool {
	return strings.Contains(strings.ToLower(p), "id")
}

func numeric(s string) bool {
	if s == "" {
		return false
	}
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		} else if r != '+' {
			return false
		}
	}
	return digits >= 7
}

func sameNumber(a, b string) bool {
	return strings.TrimPrefix(a, "+") == strings.TrimPrefix(b, "+")
}

func numbersDiffer(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if !numeric(a) || !numeric(b) {
		return !strings.EqualFold(a, b)
	}
	return !sameNumber(a, b)
}

func plausibleE164(n string) bool {
	d := strings.TrimPrefix(n, "+")
	if len(d) < 8 || len(d) > 15 {
		return false
	}
	for _, r := range d {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isRepeatingDigits(n string) bool {
	d := strings.TrimPrefix(n, "+")
	if len(d) < 8 {
		return false
	}
	first := rune(d[0])
	for _, r := range d {
		if r != first {
			return false
		}
	}
	return true
}

func isSequentialDigits(n string) bool {
	d := strings.TrimPrefix(n, "+")
	if len(d) < 8 {
		return false
	}
	asc, desc := true, true
	for i := 1; i < len(d); i++ {
		if d[i] != d[i-1]+1 && !(d[i-1] == '9' && d[i] == '0') {
			asc = false
		}
		if d[i] != d[i-1]-1 && !(d[i-1] == '0' && d[i] == '9') {
			desc = false
		}
	}
	return asc || desc
}

func isPremiumRate(n string) bool {
	d := strings.TrimPrefix(n, "+")
	prefixes := []string{
		"1900", "1976",
		"4490", "4487", "449",
		"900", "976",
		"3906",
		"338",
		"49800", "49900",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(d, p) {
			return true
		}
	}
	// NANP 1-900 / 1-976
	if strings.HasPrefix(d, "1") && len(d) >= 4 {
		nxx := d[1:4]
		if nxx == "900" || nxx == "976" {
			return true
		}
	}
	return false
}

func isPrivateHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}
