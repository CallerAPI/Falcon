package httpapi

import (
	"sort"
	"strings"

	"github.com/callerapi/falcon/internal/score"
)

// Why is one reason in words an operator reads without a manual.
type Why struct {
	Code     string `json:"code"`
	Text     string `json:"text"`
	Detail   string `json:"detail,omitempty"`
	Weight   int    `json:"weight"`
	Evidence bool   `json:"evidence,omitempty"`
}

var plainReasons = map[string]string{
	"spam_feed_hit":              "The number is on the CallerAPI spam list.",
	"voice_firewall_spam":        "Live reputation marks the number as spam.",
	"bcid_spoofed":               "A verified business owns this number, and this call did not come from it.",
	"caller_id_not_owned":        "Your customer sent a caller ID it does not own.",
	"ip_intel_block":             "The source address is on the telecom abuse list.",
	"ip_intel_hostile":           "The source network is known for abusive traffic.",
	"ip_intel_suspicious":        "The source network is often abused.",
	"caller_fanout":              "The number called many different people in the last hour.",
	"sequential_dialing":         "The number dials numbers in sequence, like an autodialer.",
	"caller_low_asr":             "Few of this number's calls get answered.",
	"caller_short_calls":         "This number's answered calls are very short.",
	"caller_hits_honeypots":      "The number called your unassigned numbers.",
	"honeypot_target":            "The call went to one of your unassigned numbers.",
	"scanner_user_agent":         "The call came from SIP scanning software.",
	"source_invite_flood":        "The source sent a burst of calls.",
	"from_invite_flood":          "The number sent a burst of calls.",
	"source_dest_scan":           "The source tried many destinations in a short time.",
	"missing_identity":           "The call has no STIR/SHAKEN signature.",
	"shaken_attest_c":            "The signer could not vouch for the caller (attestation C).",
	"shaken_attest_b":            "The signer knows the customer but not the number (attestation B).",
	"shaken_verify_failed":       "The STIR/SHAKEN signature failed verification.",
	"shaken_invalid":             "The STIR/SHAKEN header is malformed.",
	"shaken_cert_revoked":        "The signing certificate is revoked.",
	"shaken_orig_mismatch":       "The signed caller ID does not match the caller ID shown.",
	"shaken_unverifiable":        "The signature could not be checked.",
	"shaken_iat_stale":           "The signature is too old.",
	"shaken_iat_future":          "The signature is dated in the future.",
	"network_signer":             "Other Falcon installs see bad traffic from this signer.",
	"network_fingerprint":        "Other Falcon installs see bad traffic from this software.",
	"premium_rate_dest":          "The call goes to a premium-rate number.",
	"invalid_from_number":        "The caller ID is not a valid number.",
	"synthetic_from":             "The caller ID looks made up.",
	"from_equals_to":             "The caller ID is the same as the number called.",
	"privacy_id_spoof":           "The caller hides its number in a way spoofers use.",
	"anonymous_from_no_pai":      "The call is anonymous and has no network identity.",
	"from_pai_mismatch":          "The caller ID differs from the network identity.",
	"uk_mobile_from_abroad":      "The caller ID is a UK mobile number on a call from outside the UK.",
	"from_rpid_mismatch":         "The caller ID differs from the party ID.",
	"contact_private_src_public": "The SIP headers show a private address on a public call.",
	"invite_no_sdp":              "The call has no audio offer.",
	"sdp_zero_connection":        "The audio offer has no address.",
	"max_forwards_low":           "The call passed through many hops.",
	"via_hop_flood":              "The call passed through an unusual number of hops.",
	"missing_user_agent":         "The call names no software.",
	"missing_call_id":            "The call has no Call-ID.",
	"missing_from":               "The call has no caller.",
	"voice_scam":                 "The recording sounds like a scam.",
	"fas_ringback":               "The far end answered while the line still rang.",
	"fas_busy":                   "The far end answered and then played a busy tone.",
	"fas_sit":                    "The far end answered and then played an intercept message.",
	"fas_dead_air":               "The far end answered and sent no audio.",
	"fail_open":                  "Falcon could not read the call and let it through.",
}

// evidenceReasons carry no weight. They record what was heard after the
// INVITE was scored.
var evidenceReasons = map[string]bool{"voice_scam": true, "fas_ringback": true, "fas_busy": true, "fas_sit": true, "fas_dead_air": true}

// informReasons carry no weight and still belong on the call. They do not
// change the action.
var informReasons = map[string]bool{"uk_mobile_from_abroad": true}

// plainReason is the sentence for one code.
func plainReason(code string) string {
	if t, ok := plainReasons[code]; ok {
		return t
	}
	for prefix, verb := range map[string]string{"denylist_": "You blocked", "allowlist_": "You allowed"} {
		if subject, ok := strings.CutPrefix(code, prefix); ok {
			switch subject {
			case "number":
				return verb + " this number."
			case "ip":
				return verb + " this source address."
			case "spc":
				return verb + " this signer."
			}
			return verb + " this caller."
		}
	}
	if strings.HasPrefix(code, "plugin_") {
		return "A check you turned on marked this call."
	}
	return strings.ReplaceAll(code, "_", " ")
}

// explain turns reasons into sentences, heaviest first. Reasons with no
// weight are kept only when they are evidence or the only reason.
func explain(reasons []score.Reason) []Why {
	out := make([]Why, 0, len(reasons))
	for _, r := range reasons {
		ev := evidenceReasons[r.Code]
		if r.Weight <= 0 && !ev && !informReasons[r.Code] && len(reasons) > 1 {
			continue
		}
		out = append(out, Why{Code: r.Code, Text: plainReason(r.Code), Detail: r.Detail, Weight: r.Weight, Evidence: ev})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Evidence != out[j].Evidence {
			return out[i].Evidence
		}
		return out[i].Weight > out[j].Weight
	})
	return out
}

// headline is the top reason: its code and the one sentence a list row shows.
func headline(reasons []score.Reason) (code, text string) {
	w := explain(reasons)
	if len(w) == 0 {
		return "", ""
	}
	return w[0].Code, w[0].Text
}
