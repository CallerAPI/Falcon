package share

import (
	"regexp"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

// Kinds of telemetry rows. An evidence row is a call with a signal. A
// sample is a clean call sent in full for header analytics. CallerAPI
// counts a sample from the hourly rollup, not from its row.
const (
	KindEvidence = "evidence"
	KindSample   = "sample"
)

// Evidence reports whether a call carries a signal worth a full row: a
// decision other than allow, a honeypot hit, a failed verification, or a
// voice category. Every other call is clean. Clean inbound calls travel as
// hourly counts.
func Evidence(ev store.Event) bool {
	return ev.Action != score.ActionAllow ||
		ev.Honeypot ||
		ev.Verstat == "TN-Validation-Failed" ||
		(ev.VoiceCategory != "" && ev.VoiceCategory != "none")
}

// Rollup is one hour of clean calls for one key: a signer code, a sending
// tool, a calling number, or the install itself (dim install, empty key).
// Callees is the distinct called numbers of a caller over the 24 hours that
// end with the bucket. Only the count leaves the host.
type Rollup struct {
	Hour        string `json:"hour"`
	Dim         string `json:"dim"`
	Key         string `json:"key"`
	Label       string `json:"label,omitempty"`
	SPC         string `json:"spc,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Calls       int    `json:"calls"`
	Verified    int    `json:"verified,omitempty"`
	Completed   int    `json:"completed,omitempty"`
	Answered    int    `json:"answered,omitempty"`
	TalkSeconds int    `json:"talk_seconds,omitempty"`
	Callees     int    `json:"callees,omitempty"`
	FirstSeen   string `json:"first_seen,omitempty"`
	LastSeen    string `json:"last_seen,omitempty"`
}

var longDigits = regexp.MustCompile(`\d{7,}`)

// SafeLabel drops a label that holds a run of seven or more digits. A
// signer name or a User-Agent has no reason to carry a phone number.
func SafeLabel(s string) string {
	if longDigits.MatchString(s) {
		return ""
	}
	return s
}
