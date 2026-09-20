// Package alerts watches the last few minutes of decisions and posts to a
// webhook when a threshold is crossed. Operators do not watch dashboards;
// they get paged. Every fired alert is also stored for the System view.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

// Thresholds are the runtime settings. Zero disables a rule.
type Thresholds struct {
	WebhookURL string `json:"alert_webhook_url"`
	// MinCalls is the floor before a rate means anything.
	MinCalls int `json:"alert_min_calls"`
	// SignerRejectPct fires per signer when its reject rate crosses this.
	SignerRejectPct int `json:"alert_signer_reject_pct"`
	// RejectPct fires on the overall reject rate.
	RejectPct int `json:"alert_reject_pct"`
	// VerifyFailPct fires on the share of verified calls that failed.
	VerifyFailPct int `json:"alert_verify_fail_pct"`
	// TrustStaleHours fires when the STI-PA list has not refreshed.
	TrustStaleHours int `json:"alert_trust_stale_hours"`
	// CustomerRejectPct fires per customer on outbound reject rate.
	CustomerRejectPct int `json:"alert_customer_reject_pct"`
}

// Defaults are conservative: they page on real trouble, not on a busy hour.
func Defaults() Thresholds {
	return Thresholds{MinCalls: 50, SignerRejectPct: 50, RejectPct: 30, VerifyFailPct: 25, TrustStaleHours: 24, CustomerRejectPct: 30}
}

// Sources are what the watcher reads. Kept as functions so tests can stub.
type Sources struct {
	Store      store.Store
	Thresholds func(context.Context) Thresholds
	TrustAge   func() (time.Duration, bool)
	Version    string
	InstallID  string
}

// Watcher runs the rules on a timer.
type Watcher struct {
	Sources
	Window   time.Duration
	Cooldown time.Duration
	Interval time.Duration
	HTTP     *http.Client
	Now      func() time.Time
}

// Fired is one alert about to be delivered.
type Fired struct {
	Key      string
	Severity string
	Title    string
	Detail   string
	// Data is the structured part of the webhook: ids a platform can act
	// on without parsing prose.
	Data map[string]any
}

// Run evaluates until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	if w.Interval <= 0 {
		w.Interval = time.Minute
	}
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Tick(ctx)
		}
	}
}

// Tick runs the rules once.
func (w *Watcher) Tick(ctx context.Context) {
	for _, f := range w.Evaluate(ctx) {
		w.fire(ctx, f)
	}
}

// Evaluate returns what would fire now, without firing.
func (w *Watcher) Evaluate(ctx context.Context) []Fired {
	th := w.Thresholds(ctx)
	now := w.now()
	window := w.Window
	if window <= 0 {
		window = 15 * time.Minute
	}
	from := now.Add(-window)
	// The store's upper bound is exclusive; include the current second.
	to := now.Add(time.Second)
	var out []Fired

	st, err := w.Store.Stats(ctx, from, to)
	if err == nil {
		total := 0
		for _, n := range st.ByAction {
			total += n
		}
		if th.RejectPct > 0 && total >= th.MinCalls && th.MinCalls > 0 {
			pct := st.ByAction["reject"] * 100 / total
			if pct >= th.RejectPct {
				out = append(out, Fired{
					Key: "reject_rate", Severity: "warning",
					Title:  fmt.Sprintf("Reject rate %d%% over the last %s", pct, window),
					Detail: fmt.Sprintf("%d of %d screened calls were rejected. Threshold %d%%.", st.ByAction["reject"], total, th.RejectPct),
				})
			}
		}
		if th.VerifyFailPct > 0 {
			passed, failed := st.ByVerstat["TN-Validation-Passed"], st.ByVerstat["TN-Validation-Failed"]
			if v := passed + failed; v >= th.MinCalls && th.MinCalls > 0 {
				pct := failed * 100 / v
				if pct >= th.VerifyFailPct {
					out = append(out, Fired{
						Key: "verify_fail_rate", Severity: "warning",
						Title:  fmt.Sprintf("STIR/SHAKEN failures at %d%% over the last %s", pct, window),
						Detail: fmt.Sprintf("%d of %d verified PASSporTs failed. Threshold %d%%. A signer may be misconfigured or forging.", failed, v, th.VerifyFailPct),
					})
				}
			}
		}
	}

	if th.SignerRejectPct > 0 && th.MinCalls > 0 {
		parties, err := w.Store.Parties(ctx, "signer", from, to, 200)
		if err == nil {
			for _, p := range parties {
				if p.Name == "" || p.Total < th.MinCalls {
					continue
				}
				pct := p.Reject * 100 / p.Total
				if pct >= th.SignerRejectPct {
					name := p.Label
					if name == "" {
						name = "SPC " + p.Name
					}
					out = append(out, Fired{
						Key: "signer_reject:" + p.Name, Severity: "critical",
						Title:  fmt.Sprintf("Signer %s rejected at %d%%", name, pct),
						Detail: fmt.Sprintf("%d of %d calls signed by SPC %s were rejected in the last %s. Threshold %d%%. Consider a deny rule on the signer.", p.Reject, p.Total, p.Name, window, th.SignerRejectPct),
					})
				}
			}
		}
	}

	if th.CustomerRejectPct > 0 && th.MinCalls > 0 {
		parties, err := w.Store.Parties(ctx, "customer", from, to, 200)
		if err == nil {
			for _, p := range parties {
				if p.Name == "" || p.Total < th.MinCalls {
					continue
				}
				pct := p.Reject * 100 / p.Total
				if pct >= th.CustomerRejectPct {
					out = append(out, Fired{
						Key: "customer_reject:" + p.Name, Severity: "critical",
						Title:  fmt.Sprintf("Customer %s rejected at %d%%", p.Name, pct),
						Detail: fmt.Sprintf("%d of %d calls from customer %s were rejected in the last %s. Threshold %d%%. Fraud from your own platform is what regulators fine; review the account now.", p.Reject, p.Total, p.Name, window, th.CustomerRejectPct),
						Data: map[string]any{"kind": "customer_reject_rate", "customer_id": p.Name, "calls": p.Total, "rejects": p.Reject, "reject_pct": pct,
							"distinct_callees": p.Distinct, "window": window.String(), "suggested_action": "suspend_outbound_and_review"},
					})
				}
			}
		}
	}

	if th.TrustStaleHours > 0 && w.TrustAge != nil {
		if age, ok := w.TrustAge(); ok && age >= time.Duration(th.TrustStaleHours)*time.Hour {
			out = append(out, Fired{
				Key: "trust_stale", Severity: "warning",
				Title:  fmt.Sprintf("STI-PA trust list is %s old", age.Round(time.Hour)),
				Detail: "The trusted CA list has not refreshed. New signers will verify as untrusted until it does. Check outbound access to the STI-PA.",
			})
		}
	}
	return out
}

// FireNow delivers one alert from outside the timer, with the same
// cooldown per key.
func (w *Watcher) FireNow(ctx context.Context, f Fired) { w.fire(ctx, f) }

func (w *Watcher) fire(ctx context.Context, f Fired) {
	cooldown := w.Cooldown
	if cooldown <= 0 {
		cooldown = time.Hour
	}
	if last, ok, _ := w.Store.LastAlert(ctx, f.Key); ok && w.now().Sub(last) < cooldown {
		return
	}
	a := store.Alert{At: w.now(), Key: f.Key, Severity: f.Severity, Title: f.Title, Detail: f.Detail}
	if f.Data != nil {
		if b, err := json.Marshal(f.Data); err == nil {
			a.Detail += "\n" + string(b)
		}
	}
	th := w.Thresholds(ctx)
	if th.WebhookURL != "" {
		if err := w.Deliver(ctx, th.WebhookURL, f); err != nil {
			a.Error = err.Error()
			log.Printf("falcon alert %s: webhook: %v", f.Key, err)
		} else {
			a.Delivered = true
		}
	}
	if _, err := w.Store.AddAlert(ctx, a); err != nil {
		log.Printf("falcon alert store: %v", err)
	}
	log.Printf("falcon alert [%s] %s", f.Severity, f.Title)
}

// Deliver posts one alert. The body carries a Slack-compatible text field
// and a structured falcon object for everything else.
func (w *Watcher) Deliver(ctx context.Context, url string, f Fired) error {
	payload := map[string]any{
		"text": fmt.Sprintf("[falcon %s] %s\n%s", f.Severity, f.Title, f.Detail),
		"falcon": map[string]any{
			"key": f.Key, "severity": f.Severity, "title": f.Title, "detail": f.Detail,
			"install_id": w.InstallID, "version": w.Version, "at": w.now().Format(time.RFC3339),
			"data": f.Data,
		},
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(url), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "falcon/"+w.Version)
	client := w.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now().UTC()
}
