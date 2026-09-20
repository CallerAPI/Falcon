package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/score"
)

// Event is one screened SIP request.
type Event struct {
	ID         int64        `json:"id"`
	ReceivedAt time.Time    `json:"received_at"`
	Action     score.Action `json:"action"`
	RiskScore  int          `json:"risk_score"`
	SourceIP   string       `json:"source_ip"`
	From       string       `json:"from"`
	To         string       `json:"to"`
	CallID     string       `json:"call_id"`
	UserAgent  string       `json:"user_agent"`
	Attest     string       `json:"shaken_attest,omitempty"`
	Verstat    string       `json:"verstat,omitempty"`
	SignerSPC  string       `json:"signer_spc,omitempty"`
	SignerName string       `json:"signer_name,omitempty"`
	Provider   string       `json:"provider,omitempty"`
	// Fingerprint identifies the sending software, never the parties.
	Fingerprint string         `json:"fingerprint,omitempty"`
	Reasons     []score.Reason `json:"reasons"`
	// Direction is inbound (default) or outbound: the operator's own
	// customer placing the call. Customer is the operator's account label.
	Direction string `json:"direction,omitempty"`
	Customer  string `json:"customer,omitempty"`
	// Outcome fields arrive after the call from POST /v1/outcome.
	Answered    *bool  `json:"answered,omitempty"`
	DurationS   *int   `json:"duration_s,omitempty"`
	HangupCause string `json:"hangup_cause,omitempty"`
	// Honeypot marks a call to a number the operator listed as unassigned.
	Honeypot bool `json:"honeypot,omitempty"`
	// Sampled marks that the switch was asked to hand over audio.
	Sampled bool `json:"sampled,omitempty"`
	// VoiceCategory and VoiceScore are filled from the voice sample when
	// an event is exported; the transcript never travels with them.
	VoiceCategory string  `json:"voice_category,omitempty"`
	VoiceScore    float64 `json:"voice_score,omitempty"`
	// Shaken is the verification result as JSON, kept for the drawer.
	Shaken   json.RawMessage `json:"shaken,omitempty"`
	RawSIP   string          `json:"raw_sip,omitempty"`
	Switch   string          `json:"switch,omitempty"`
	Exported bool            `json:"exported"`
}

// Filter narrows an event query. Zero values mean no constraint. BeforeID is
// a cursor: rows with a smaller id, newest first.
type Filter struct {
	From        time.Time
	To          time.Time
	Action      string
	Verstat     string
	IP          string
	SPC         string
	Provider    string
	Fingerprint string
	Direction   string
	Customer    string
	Number      string
	Q           string
	BeforeID    int64
	Limit       int
}

// Stats is dashboard aggregation for one window.
type Stats struct {
	Total        int            `json:"total"`
	ByAction     map[string]int `json:"by_action"`
	ByVerstat    map[string]int `json:"by_verstat"`
	ByAttest     map[string]int `json:"by_attest"`
	AvgScore     float64        `json:"avg_score"`
	TopIPs       []NameCount    `json:"top_ips"`
	TopUAs       []NameCount    `json:"top_user_agents"`
	TopProviders []NameCount    `json:"top_providers"`
	TopSigners   []NameCount    `json:"top_signers"`
	TopReasons   []NameCount    `json:"top_reasons"`
	Timeseries   []Bucket       `json:"timeseries"`
	StepSeconds  int            `json:"step_seconds"`
}

type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Bucket is one timeseries point with the action split.
type Bucket struct {
	TS        time.Time `json:"ts"`
	Count     int       `json:"count"`
	Allow     int       `json:"allow"`
	Flag      int       `json:"flag"`
	Challenge int       `json:"challenge"`
	Reject    int       `json:"reject"`
	Avg       float64   `json:"avg_score"`
}

// Party is a per-entity summary for providers, signers, and source IPs.
type Party struct {
	Name     string  `json:"name"`
	Label    string  `json:"label,omitempty"`
	Total    int     `json:"total"`
	Reject   int     `json:"reject"`
	Flag     int     `json:"flag"`
	AvgScore float64 `json:"avg_score"`
	AttestA  int     `json:"attest_a"`
	AttestB  int     `json:"attest_b"`
	AttestC  int     `json:"attest_c"`
	Passed   int     `json:"verstat_passed"`
	Failed   int     `json:"verstat_failed"`
	Distinct int     `json:"distinct_from"`
	// NetworkScore and NetworkInstalls come from the CallerAPI feed when
	// the grouping is by signer or fingerprint. Zero means no row.
	NetworkScore    int       `json:"network_score,omitempty"`
	NetworkInstalls int       `json:"network_installs,omitempty"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

// Store persists events, rules, and install settings.
// AuditEntry records who changed what. Every mutation through the API
// writes one.
type AuditEntry struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Subject string    `json:"subject"`
	Detail  string    `json:"detail,omitempty"`
}

// Alert is one fired condition, kept for the dashboard.
type Alert struct {
	ID        int64     `json:"id"`
	At        time.Time `json:"at"`
	Key       string    `json:"key"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail"`
	Delivered bool      `json:"delivered"`
	Error     string    `json:"error,omitempty"`
}

type Store interface {
	Insert(ctx context.Context, ev Event) (int64, error)
	Recent(ctx context.Context, limit int) ([]Event, error)
	Query(ctx context.Context, f Filter) ([]Event, error)
	Get(ctx context.Context, id int64) (Event, error)
	Stats(ctx context.Context, from, to time.Time) (Stats, error)
	Histogram(ctx context.Context, from, to time.Time) ([]int, error)
	Parties(ctx context.Context, by string, from, to time.Time, limit int) ([]Party, error)
	Unexported(ctx context.Context, limit int) ([]Event, error)
	MarkExported(ctx context.Context, ids []int64) error
	Prune(ctx context.Context, before time.Time) (int64, error)
	ScrubRawSIP(ctx context.Context, before time.Time) (int64, error)
	Rules(ctx context.Context) ([]lists.Rule, error)
	AddRule(ctx context.Context, r lists.Rule) (lists.Rule, error)
	DeleteRule(ctx context.Context, id int64) error
	KVGet(ctx context.Context, key string) (string, error)
	KVSet(ctx context.Context, key, value string) error
	Audit(ctx context.Context, e AuditEntry) error
	AuditLog(ctx context.Context, limit int) ([]AuditEntry, error)
	AddAlert(ctx context.Context, a Alert) (int64, error)
	Alerts(ctx context.Context, limit int) ([]Alert, error)
	LastAlert(ctx context.Context, key string) (time.Time, bool, error)
	SetOutcome(ctx context.Context, callID string, o Outcome) (Event, error)
	MarkSampled(ctx context.Context, id int64) error
	CallerActivity(ctx context.Context, from string, since time.Time) (Activity, error)
	CustomerActivity(ctx context.Context, customer string, since time.Time) (Activity, error)
	WindowActivity(ctx context.Context, since time.Time) (Activity, error)
	CountReason(ctx context.Context, from, to time.Time, code string) (int, error)
	Customers(ctx context.Context) ([]Customer, error)
	Customer(ctx context.Context, id string) (Customer, bool, error)
	PutCustomer(ctx context.Context, c Customer) error
	DeleteCustomer(ctx context.Context, id string) error
	AddVoiceSample(ctx context.Context, v VoiceSample) (int64, error)
	UpdateVoiceSample(ctx context.Context, v VoiceSample) error
	VoiceSamples(ctx context.Context, limit int) ([]VoiceSample, error)
	VoiceSampleForEvent(ctx context.Context, eventID int64) (VoiceSample, bool, error)
	RecentPHashes(ctx context.Context, since time.Time, limit int) ([]string, error)
	SamplesSince(ctx context.Context, since time.Time, customer string) (int, error)
	Close() error
}

func ReasonsJSON(reasons []score.Reason) string {
	if len(reasons) == 0 {
		return "[]"
	}
	b, err := json.Marshal(reasons)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func ParseReasons(s string) []score.Reason {
	if s == "" {
		return nil
	}
	var out []score.Reason
	if json.Unmarshal([]byte(s), &out) != nil {
		return nil
	}
	return out
}

// StepFor picks a bucket width that yields about 60 to 120 points.
func StepFor(from, to time.Time) time.Duration {
	span := to.Sub(from)
	switch {
	case span <= 2*time.Hour:
		return time.Minute
	case span <= 8*time.Hour:
		return 5 * time.Minute
	case span <= 48*time.Hour:
		return 30 * time.Minute
	case span <= 14*24*time.Hour:
		return 3 * time.Hour
	default:
		return 24 * time.Hour
	}
}
