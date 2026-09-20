package score

// Action is the switch-facing decision.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionFlag      Action = "flag"
	ActionChallenge Action = "challenge"
	ActionReject    Action = "reject"
)

// Reason is one scored signal that contributed to the decision.
type Reason struct {
	Code     string `json:"code"`
	Weight   int    `json:"weight"`
	Detail   string `json:"detail"`
	Category string `json:"category"`
}

// Result is the full screen outcome.
type Result struct {
	// Sample asks the switch to hand Falcon the first seconds of audio.
	// Set by the sampler after scoring, never by the engine.
	Sample      bool              `json:"sample"`
	Action      Action            `json:"action"`
	RiskScore   int               `json:"risk_score"`
	RiskBand    string            `json:"risk_band"`
	SIPStatus   int               `json:"sip_status"`
	SIPReason   string            `json:"sip_reason"`
	Reasons     []Reason          `json:"reasons"`
	Signals     Signals           `json:"signals"`
	Headers     map[string]string `json:"headers_to_set"`
	SwitchHints SwitchHints       `json:"switch_hints"`
	Upsell      Upsell            `json:"upsell"`
}

// Signals are extracted facts that back the score.
type Signals struct {
	Method       string `json:"method"`
	From         string `json:"from"`
	To           string `json:"to"`
	CallID       string `json:"call_id"`
	UserAgent    string `json:"user_agent"`
	SourceIP     string `json:"source_ip"`
	ShakenAttest string `json:"shaken_attest,omitempty"`
	ShakenOrigID string `json:"shaken_orig_id,omitempty"`
	ViaHops      int    `json:"via_hops"`
	FeedHit      bool   `json:"feed_hit"`
	FirewallSpam bool   `json:"firewall_spam"`
	FeedEnabled  bool   `json:"feed_enabled"`
	FirewallOn   bool   `json:"firewall_enabled"`
	// IPProvider, IPRisk and IPTags come from the telecom IP intel table.
	IPProvider string   `json:"ip_provider,omitempty"`
	IPRisk     string   `json:"ip_risk,omitempty"`
	IPTags     []string `json:"ip_tags,omitempty"`
	// Direction, Customer, and the caller behaviour fields back the
	// outbound and behaviour rules.
	Direction             string `json:"direction,omitempty"`
	Customer              string `json:"customer,omitempty"`
	Honeypot              bool   `json:"honeypot,omitempty"`
	CallerCalls           int    `json:"caller_calls,omitempty"`
	CallerDistinctCallees int    `json:"caller_distinct_callees,omitempty"`
	CallerASR             int    `json:"caller_asr,omitempty"`
	CallerACD             int    `json:"caller_acd,omitempty"`
	CallerSequential      bool   `json:"caller_sequential,omitempty"`
	// NetworkSignerScore and NetworkFingerprintScore come from the CallerAPI
	// feed built from every sharing install. Zero means no row.
	NetworkSignerScore      int `json:"network_signer_score,omitempty"`
	NetworkFingerprintScore int `json:"network_fingerprint_score,omitempty"`
	// Verstat, SignerSPC and SignerName come from PASSporT verification.
	Verstat    string `json:"verstat,omitempty"`
	SignerSPC  string `json:"signer_spc,omitempty"`
	SignerName string `json:"signer_name,omitempty"`
	// ListRule and ListKind name the operator rule that decided the call.
	ListRule int64  `json:"list_rule,omitempty"`
	ListKind string `json:"list_kind,omitempty"`
}

// SwitchHints map the action onto common switch controls.
type SwitchHints struct {
	AsteriskHangupCause   int    `json:"asterisk_hangup_cause"`
	FreeSWITCHHangupCause string `json:"freeswitch_hangup_cause"`
	KamailioReply         string `json:"kamailio_reply"`
}

// Upsell describes paid add-ons that are off on this install.
type Upsell struct {
	SpamFeed      AddOn `json:"spam_feed"`
	VoiceFirewall AddOn `json:"voice_firewall"`
}

// AddOn is one optional paid connection.
type AddOn struct {
	Available bool   `json:"available"`
	Connected bool   `json:"connected"`
	URL       string `json:"url"`
	Headline  string `json:"headline"`
	Detail    string `json:"detail"`
}

// Thresholds convert a score into an action.
type Thresholds struct {
	Flag      int
	Challenge int
	Reject    int
}

func (t Thresholds) Action(score int) Action {
	switch {
	case score >= t.Reject:
		return ActionReject
	case score >= t.Challenge:
		return ActionChallenge
	case score >= t.Flag:
		return ActionFlag
	default:
		return ActionAllow
	}
}

func (a Action) Band() string {
	switch a {
	case ActionReject:
		return "high"
	case ActionChallenge:
		return "elevated"
	case ActionFlag:
		return "medium"
	default:
		return "low"
	}
}

func (a Action) SIP() (int, string) {
	switch a {
	case ActionReject:
		return 603, "Decline"
	case ActionChallenge:
		return 407, "Proxy Authentication Required"
	default:
		return 0, ""
	}
}

func (a Action) Hints() SwitchHints {
	switch a {
	case ActionReject:
		return SwitchHints{21, "CALL_REJECTED", "603 Decline"}
	case ActionChallenge:
		return SwitchHints{21, "CALL_REJECTED", "407 Proxy Authentication Required"}
	default:
		return SwitchHints{0, "", ""}
	}
}
