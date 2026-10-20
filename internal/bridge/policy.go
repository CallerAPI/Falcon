package bridge

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

// Plan is what the bridge does with one INVITE.
type Plan int

const (
	// Pass answers 503 before answer. The switch moves to its next vendor
	// and Falcon is out of the call.
	Pass Plan = iota
	// Reject answers 603. Only a hard block in enforce mode does this.
	Reject
	// Carry bridges the call back to the switch or on to a vendor route,
	// relays the audio, and records it.
	Carry
)

// Carry reasons, stored on the bridged call.
const (
	CarryChallenge = "challenge"
	CarryReject    = "reject"
	CarryFanout    = "fanout_sample"
	CarryClean     = "fas_sample"
	CarryRoute     = "route"
)

// Decision is the plan and, for Carry, why.
type Decision struct {
	Plan   Plan
	Reason string
}

// sampler counts calls so one in N is taken without a random source.
type sampler struct{ n atomic.Uint64 }

func (s *sampler) take(every int) bool {
	if every <= 0 {
		return false
	}
	return s.n.Add(1)%uint64(every) == 0
}

// Policy turns a screen result into a plan.
type Policy struct {
	fanout sampler
	clean  sampler
}

// Decide reads the real decision, which monitor mode moves into
// X-Falcon-Monitor, and the route's carry rule.
func (p *Policy) Decide(res score.Result, mode string, route *store.Route, fanoutEvery, cleanEvery int) Decision {
	real := res.Action
	if held := res.Headers["X-Falcon-Monitor"]; held != "" {
		real = score.Action(held)
	}
	switch {
	case real == score.ActionReject && mode == config.ModeEnforce:
		return Decision{Plan: Reject}
	case route != nil && route.Carry == store.CarryAll:
		return Decision{Plan: Carry, Reason: CarryRoute}
	case real == score.ActionReject:
		return Decision{Plan: Carry, Reason: CarryReject}
	case real == score.ActionChallenge:
		return Decision{Plan: Carry, Reason: CarryChallenge}
	case real == score.ActionFlag && fanoutOnly(res) && p.fanout.take(fanoutEvery):
		return Decision{Plan: Carry, Reason: CarryFanout}
	case real == score.ActionAllow && p.clean.take(cleanEvery):
		return Decision{Plan: Carry, Reason: CarryClean}
	}
	return Decision{Plan: Pass}
}

// fanoutOnly is a flag whose weight comes from caller_fanout. On a
// wholesale ingress that is a call center as often as a robocaller, so a
// sample of those calls is heard and the rest pass.
func fanoutOnly(res score.Result) bool {
	for _, r := range res.Reasons {
		if r.Code == "caller_fanout" && r.Weight > 0 {
			return true
		}
	}
	return false
}

// routeTable matches the longest tech prefix of a dialed user part.
type routeTable struct {
	mu     sync.RWMutex
	routes []store.Route
}

func (t *routeTable) set(routes []store.Route) {
	sorted := append([]store.Route(nil), routes...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && len(sorted[j].Prefix) > len(sorted[j-1].Prefix); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	t.mu.Lock()
	t.routes = sorted
	t.mu.Unlock()
}

func (t *routeTable) match(user string) *store.Route {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for i := range t.routes {
		if t.routes[i].Prefix != "" && strings.HasPrefix(user, t.routes[i].Prefix) {
			r := t.routes[i]
			return &r
		}
	}
	return nil
}
