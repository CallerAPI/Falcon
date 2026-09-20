package voice

import (
	"context"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

// Budget bounds how many clips are taken. A model that hears every call
// is a cost nobody can carry; a model that hears one in a thousand chosen
// by signaling is cheap and sharp.
type Budget struct {
	PerHour            int
	PerCustomerPerHour int
	ClipSeconds        int
}

// DefaultBudget is sixty clips an hour, ten per customer, twenty seconds.
func DefaultBudget() Budget { return Budget{PerHour: 60, PerCustomerPerHour: 10, ClipSeconds: 20} }

// Sampler decides which calls get audio.
type Sampler struct {
	Store  store.Store
	Budget Budget
	// Enabled is false when there is no reason to take clips at all: no
	// provider and no interest in repeat-recording detection.
	Enabled bool
}

// Trigger names why a call was chosen.
type Trigger string

const (
	TriggerNone         Trigger = ""
	TriggerHoneypot     Trigger = "honeypot_target"
	TriggerSequential   Trigger = "sequential_dialing"
	TriggerFanout       Trigger = "caller_fanout"
	TriggerLowASR       Trigger = "caller_low_asr"
	TriggerShortCalls   Trigger = "caller_short_calls"
	TriggerNetwork      Trigger = "network_reputation"
	TriggerOutboundRisk Trigger = "outbound_flagged"
)

// Decide returns whether to ask for audio and why. It never samples a
// rejected call: there will be no audio.
func (s *Sampler) Decide(ctx context.Context, res score.Result, customer string) (bool, Trigger) {
	if s == nil || !s.Enabled || res.Action == score.ActionReject {
		return false, TriggerNone
	}
	trigger := TriggerNone
	for _, r := range res.Reasons {
		switch r.Code {
		case "honeypot_target", "caller_hits_honeypots":
			trigger = TriggerHoneypot
		case "sequential_dialing":
			if trigger == TriggerNone {
				trigger = TriggerSequential
			}
		case "caller_fanout":
			if trigger == TriggerNone {
				trigger = TriggerFanout
			}
		case "caller_low_asr":
			if trigger == TriggerNone {
				trigger = TriggerLowASR
			}
		case "caller_short_calls":
			if trigger == TriggerNone {
				trigger = TriggerShortCalls
			}
		case "network_signer", "network_fingerprint":
			if trigger == TriggerNone {
				trigger = TriggerNetwork
			}
		}
	}
	if trigger == TriggerNone && res.Signals.Direction == "outbound" && res.Action != score.ActionAllow {
		trigger = TriggerOutboundRisk
	}
	if trigger == TriggerNone {
		return false, TriggerNone
	}
	hour := time.Now().Add(-time.Hour)
	if n, err := s.Store.SamplesSince(ctx, hour, ""); err != nil || n >= s.Budget.PerHour {
		return false, TriggerNone
	}
	if customer != "" {
		if n, err := s.Store.SamplesSince(ctx, hour, customer); err != nil || n >= s.Budget.PerCustomerPerHour {
			return false, TriggerNone
		}
	}
	return true, trigger
}
