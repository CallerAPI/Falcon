package score

import (
	"strings"
	"unicode"

	"github.com/callerapi/falcon/internal/sipmsg"
)

// ReasonUKMobileFromAbroad records a UK mobile caller ID on a call from
// an international peer. The weight is 0, so it does not change the action.
const ReasonUKMobileFromAbroad = "uk_mobile_from_abroad"

// HeaderCLIWithhold tells the switch to hide the caller ID. Falcon sets it
// to 1 only when withhold is enforce.
const HeaderCLIWithhold = "X-Falcon-CLI-Withhold"

// PresentationNumber is the caller ID the callee would see. It is the From
// user. When Privacy is none, it is the P-Asserted-Identity user if that
// user is set. Diversion and History-Info are not read.
func PresentationNumber(s sipmsg.Snapshot) string {
	if privacyHas(s.Privacy, "none") && !privacyHas(s.Privacy, "id") && s.PAIUser != "" {
		return s.PAIUser
	}
	return s.FromUser
}

// UKMobile reports a presentation number in the +447 range.
func UKMobile(n string) bool {
	return strings.HasPrefix(n, "+447") && numeric(n)
}

// WithheldIdentity reports a call whose From user is anonymous and whose
// Privacy header carries id. That pair is a withheld caller ID.
func WithheldIdentity(s sipmsg.Snapshot) bool {
	return isAnonymous(s.FromUser) && privacyHas(s.Privacy, "id")
}

// ReputationNumber is the number for the spam feed, live reputation, and
// number rules. On a withheld call it is the P-Asserted-Identity number.
// Callers must not copy it into a header the callee can see.
func ReputationNumber(s sipmsg.Snapshot) string {
	if WithheldIdentity(s) && numeric(s.PAIUser) {
		return s.PAIUser
	}
	return s.FromUser
}

func privacyHas(header, token string) bool {
	token = strings.ToLower(token)
	for _, part := range strings.FieldsFunc(strings.ToLower(header), func(r rune) bool {
		return r == ';' || r == ',' || unicode.IsSpace(r)
	}) {
		if part == token {
			return true
		}
	}
	return false
}

func reasonHas(reasons []Reason, code string) bool {
	for _, r := range reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}
