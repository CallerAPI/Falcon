package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

// Overview is everything the home screen shows, in one request: the state
// of protection, four numbers, the trend, what needs a decision, and the
// latest calls Falcon stopped or flagged.
type Overview struct {
	Range    string             `json:"range"`
	From     time.Time          `json:"from"`
	To       time.Time          `json:"to"`
	Status   OverviewStatus     `json:"status"`
	Totals   OverviewTotals     `json:"totals"`
	Latency  store.LatencyStats `json:"latency"`
	Series   []store.Bucket     `json:"series"`
	Step     int                `json:"step_seconds"`
	Insights []Insight          `json:"insights"`
	Recent   []RecentCall       `json:"recent"`
}

// OverviewStatus says whether Falcon is protecting the switch right now.
type OverviewStatus struct {
	Mode        string         `json:"mode"`
	FASMode     string         `json:"fas_mode"`
	Profile     string         `json:"profile"`
	SIP         map[string]any `json:"sip"`
	LastCallAt  *time.Time     `json:"last_call_at,omitempty"`
	Version     string         `json:"version"`
	Update      string         `json:"update,omitempty"`
	Sharing     bool           `json:"sharing"`
	Voice       string         `json:"voice"`
	CLIWithhold string         `json:"cli_withhold"`
	InstallID   string         `json:"install_id"`
	RecordingOn bool           `json:"recording"`
}

// OverviewTotals counts calls by what Falcon did.
type OverviewTotals struct {
	Screened    int     `json:"screened"`
	Blocked     int     `json:"blocked"`
	Flagged     int     `json:"flagged"`
	Allowed     int     `json:"allowed"`
	Held        int     `json:"held"`
	Bridged     int     `json:"bridged"`
	Recorded    int     `json:"recorded"`
	FAS         int     `json:"fas"`
	FASSeconds  float64 `json:"fas_seconds"`
	CLIWithhold int     `json:"cli_withhold"`
}

// RecentCall is one row of the home screen list: the newest stopped call
// from one caller. Calls counts that caller's stopped calls in the scan.
type RecentCall struct {
	ID        int64     `json:"id"`
	At        time.Time `json:"at"`
	Action    string    `json:"action"`
	Held      bool      `json:"held,omitempty"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Direction string    `json:"direction,omitempty"`
	Code      string    `json:"code,omitempty"`
	Why       string    `json:"why"`
	Score     int       `json:"score"`
	Calls     int       `json:"calls"`
}

const recentRows = 8

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	from, to := windowFrom(r)
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "24h"
	}
	ov, err := s.overview(r.Context(), rng, from, to)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *Server) overview(ctx context.Context, rng string, from, to time.Time) (Overview, error) {
	st, err := s.Store.Stats(ctx, from, to)
	if err != nil {
		return Overview{}, err
	}
	settings := s.Settings(ctx)
	ov := Overview{Range: rng, From: from, To: to, Series: st.Timeseries, Step: st.StepSeconds, Insights: []Insight{}, Recent: []RecentCall{}}
	ov.Totals = OverviewTotals{
		Screened: st.Total,
		Blocked:  st.ByAction["reject"],
		Flagged:  st.ByAction["flag"] + st.ByAction["challenge"],
		Allowed:  st.ByAction["allow"],
	}
	if n, err := s.Store.HeldCount(ctx, from, to); err == nil {
		ov.Totals.Held = n
	}
	if n, err := s.Store.CountReason(ctx, from, to, score.ReasonUKMobileFromAbroad); err == nil {
		ov.Totals.CLIWithhold = n
	}
	if mt, err := s.Store.MediaTotals(ctx, from, to); err == nil {
		ov.Totals.Bridged, ov.Totals.FAS, ov.Totals.FASSeconds = mt.Bridged, mt.FAS, mt.FASSeconds
		ov.Totals.Recorded = mt.Recorded
	}
	if ov.Totals.Recorded == 0 {
		if samples, err := s.Store.VoiceSamplesSince(ctx, from, to, 1000); err == nil {
			for _, v := range samples {
				if v.HasAudio() || v.Transcript != "" {
					ov.Totals.Recorded++
				}
			}
		}
	}
	if lat, err := s.Store.Latency(ctx, from, to); err == nil {
		ov.Latency = lat
	}
	ov.Status = OverviewStatus{
		Mode: settings.Mode, FASMode: settings.FASMode, CLIWithhold: settings.CLIWithhold, Profile: s.Cfg.Profile, SIP: s.sipStatus(),
		Version: Version, Sharing: s.Cfg.Share, Voice: providerName(s.VoiceProvider), InstallID: s.InstallID,
		RecordingOn: s.Media != nil || (s.Sampler != nil && s.Sampler.Enabled),
	}
	if rel := s.currentRelease(); rel.Newer && rel.Latest != "" {
		ov.Status.Update = rel.Latest
	}
	if last, err := s.Store.LastEventAt(ctx); err == nil && !last.IsZero() {
		ov.Status.LastCallAt = &last
	}
	if recent, err := s.Store.Query(ctx, store.Filter{From: from, To: to, Verdict: store.VerdictStopped, Limit: 200}); err == nil {
		ov.Recent = groupRecent(recent)
	}
	ov.Insights = s.insights(ctx, from, to, ov)
	return ov, nil
}

// groupRecent keeps the newest stopped call per caller, so one dialer
// does not fill the list. The events arrive newest first.
func groupRecent(events []store.Event) []RecentCall {
	out := []RecentCall{}
	byCaller := map[string]int{}
	for _, ev := range events {
		key := ev.From
		if key == "" {
			key = "#" + strconv.FormatInt(ev.ID, 10)
		}
		if i, ok := byCaller[key]; ok {
			out[i].Calls++
			continue
		}
		if len(out) == recentRows {
			continue
		}
		byCaller[key] = len(out)
		code, why := headline(ev.Reasons)
		out = append(out, RecentCall{
			ID: ev.ID, At: ev.ReceivedAt, Action: string(ev.Action), Held: ev.Held, From: ev.From, To: ev.To,
			Direction: ev.Direction, Code: code, Why: why, Score: ev.RiskScore, Calls: 1,
		})
	}
	return out
}
