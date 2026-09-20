package httpapi

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/shaken"
)

// metrics is a small Prometheus text exposition without a dependency.
// Counters live for the process. Gauges are read at scrape time.
type metrics struct {
	mu        sync.Mutex
	screens   int64
	byAction  map[string]int64
	byVerstat map[string]int64
	byAttest  map[string]int64
	pending   int64
	latencyNs int64
	latencyN  int64
	hardBlock int64
	outcomes  int64
	answered  int64
	talkSecs  int64
	clips     int64
	monologue int64
	repeats   int64
}

func (m *metrics) outcome(answered bool, seconds int) {
	m.mu.Lock()
	m.outcomes++
	if answered {
		m.answered++
		m.talkSecs += int64(seconds)
	}
	m.mu.Unlock()
}

func (m *metrics) clip(monologue bool, repeats int) {
	m.mu.Lock()
	m.clips++
	if monologue {
		m.monologue++
	}
	if repeats > 0 {
		m.repeats++
	}
	m.mu.Unlock()
}

func newMetrics() *metrics {
	return &metrics{byAction: map[string]int64{}, byVerstat: map[string]int64{}, byAttest: map[string]int64{}}
}

func (m *metrics) observe(res score.Result, v *shaken.Result, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.screens++
	m.byAction[string(res.Action)]++
	if res.Signals.ShakenAttest != "" {
		m.byAttest[res.Signals.ShakenAttest]++
	}
	if v != nil {
		m.byVerstat[v.Verstat]++
		if v.Pending {
			m.pending++
		}
	} else {
		m.byVerstat["none"]++
	}
	if res.Headers["X-Falcon-Block"] != "" {
		m.hardBlock++
	}
	m.latencyNs += d.Nanoseconds()
	m.latencyN++
}

func (m *metrics) write(w io.Writer, s *Server) {
	m.mu.Lock()
	screens, pending, hard := m.screens, m.pending, m.hardBlock
	latNs, latN := m.latencyNs, m.latencyN
	outcomes, answered, talk, clips, mono, repeats := m.outcomes, m.answered, m.talkSecs, m.clips, m.monologue, m.repeats
	actions := copyMap(m.byAction)
	verstats := copyMap(m.byVerstat)
	attests := copyMap(m.byAttest)
	m.mu.Unlock()

	fmt.Fprintf(w, "# HELP falcon_screens_total Screened SIP requests since start.\n# TYPE falcon_screens_total counter\nfalcon_screens_total %d\n", screens)
	writeLabelled(w, "falcon_screens_by_action_total", "Screened requests by action.", "action", actions)
	writeLabelled(w, "falcon_shaken_verstat_total", "PASSporT verification outcomes.", "verstat", verstats)
	writeLabelled(w, "falcon_shaken_attest_total", "PASSporT attestation levels seen.", "attest", attests)
	fmt.Fprintf(w, "# HELP falcon_shaken_pending_total Verifications that returned before the certificate fetch finished.\n# TYPE falcon_shaken_pending_total counter\nfalcon_shaken_pending_total %d\n", pending)
	fmt.Fprintf(w, "# HELP falcon_hard_blocks_total Requests rejected by a list, the feed, or IP intel.\n# TYPE falcon_hard_blocks_total counter\nfalcon_hard_blocks_total %d\n", hard)
	fmt.Fprintf(w, "# HELP falcon_screen_latency_seconds_sum Total time spent screening.\n# TYPE falcon_screen_latency_seconds_sum counter\nfalcon_screen_latency_seconds_sum %.6f\n", float64(latNs)/1e9)
	fmt.Fprintf(w, "# HELP falcon_screen_latency_seconds_count Screens measured.\n# TYPE falcon_screen_latency_seconds_count counter\nfalcon_screen_latency_seconds_count %d\n", latN)
	fmt.Fprintf(w, "# HELP falcon_call_outcomes_total Calls with a reported outcome.\n# TYPE falcon_call_outcomes_total counter\nfalcon_call_outcomes_total %d\n", outcomes)
	fmt.Fprintf(w, "# HELP falcon_calls_answered_total Reported calls that were answered.\n# TYPE falcon_calls_answered_total counter\nfalcon_calls_answered_total %d\n", answered)
	fmt.Fprintf(w, "# HELP falcon_talk_seconds_total Talk time over answered calls.\n# TYPE falcon_talk_seconds_total counter\nfalcon_talk_seconds_total %d\n", talk)
	fmt.Fprintf(w, "# HELP falcon_voice_clips_total Audio clips received.\n# TYPE falcon_voice_clips_total counter\nfalcon_voice_clips_total %d\n", clips)
	fmt.Fprintf(w, "# HELP falcon_voice_monologue_total Clips where one side talked into silence.\n# TYPE falcon_voice_monologue_total counter\nfalcon_voice_monologue_total %d\n", mono)
	fmt.Fprintf(w, "# HELP falcon_voice_repeats_total Clips that matched an earlier recording.\n# TYPE falcon_voice_repeats_total counter\nfalcon_voice_repeats_total %d\n", repeats)

	if s.Feed != nil {
		n, _, _ := s.Feed.Status()
		fmt.Fprintf(w, "# HELP falcon_spam_feed_numbers Numbers loaded from the spam feed.\n# TYPE falcon_spam_feed_numbers gauge\nfalcon_spam_feed_numbers %d\n", n)
	}
	if s.IPIntel != nil {
		n, _, _ := s.IPIntel.Status()
		fmt.Fprintf(w, "# HELP falcon_ip_intel_blocks CIDR blocks loaded.\n# TYPE falcon_ip_intel_blocks gauge\nfalcon_ip_intel_blocks %d\n", n)
	}
	if s.Trust != nil {
		st := s.Trust.Status()
		fmt.Fprintf(w, "# HELP falcon_shaken_roots Trusted STI-CA roots loaded.\n# TYPE falcon_shaken_roots gauge\nfalcon_shaken_roots %d\n", st.Roots)
		fmt.Fprintf(w, "# HELP falcon_shaken_revoked Revoked serials loaded from the STI-PA CRL.\n# TYPE falcon_shaken_revoked gauge\nfalcon_shaken_revoked %d\n", st.Revoked)
	}
	if s.Verifier != nil {
		certs, inflight := s.Verifier.CacheStats()
		fmt.Fprintf(w, "# HELP falcon_shaken_cached_chains Certificate chains in cache.\n# TYPE falcon_shaken_cached_chains gauge\nfalcon_shaken_cached_chains %d\n", certs)
		fmt.Fprintf(w, "# HELP falcon_shaken_inflight_fetches Certificate fetches in progress.\n# TYPE falcon_shaken_inflight_fetches gauge\nfalcon_shaken_inflight_fetches %d\n", inflight)
	}
	fmt.Fprintf(w, "# HELP falcon_rules Operator allow and deny rules indexed.\n# TYPE falcon_rules gauge\nfalcon_rules %d\n", s.ruleIndex().Count())
	fmt.Fprintf(w, "# HELP falcon_stream_clients Open /v1/stream connections.\n# TYPE falcon_stream_clients gauge\nfalcon_stream_clients %d\n", s.hub.count())
	fmt.Fprintf(w, "# HELP falcon_uptime_seconds Seconds since start.\n# TYPE falcon_uptime_seconds gauge\nfalcon_uptime_seconds %d\n", int(time.Since(s.StartedAt).Seconds()))
	fmt.Fprintf(w, "# HELP falcon_build_info Build information.\n# TYPE falcon_build_info gauge\nfalcon_build_info{version=%q} 1\n", Version)
}

func writeLabelled(w io.Writer, name, help, label string, values map[string]int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{%s=%q} %d\n", name, label, k, values[k])
	}
}

func copyMap(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
