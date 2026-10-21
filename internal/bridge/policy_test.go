package bridge

import (
	"testing"

	"github.com/callerapi/falcon/internal/score"
)

func TestDecideCarriesEveryCallButHardBlocksWhenCarryAllIsOn(t *testing.T) {
	var p Policy
	all := Rules{Mode: "enforce", CarryAll: true}
	cases := []struct {
		action score.Action
		plan   Plan
		reason string
	}{
		{score.ActionAllow, Carry, CarryEvery},
		{score.ActionFlag, Carry, CarryEvery},
		{score.ActionChallenge, Carry, CarryChallenge},
		{score.ActionReject, Reject, ""},
	}
	for _, c := range cases {
		d := p.Decide(score.Result{Action: c.action, Headers: map[string]string{}}, all, nil)
		if d.Plan != c.plan || d.Reason != c.reason {
			t.Errorf("%s: got %v %q, want %v %q", c.action, d.Plan, d.Reason, c.plan, c.reason)
		}
	}
	if d := p.Decide(score.Result{Action: score.ActionAllow, Headers: map[string]string{}}, Rules{Mode: "enforce"}, nil); d.Plan != Pass {
		t.Fatalf("without carry all a clean call must pass, got %v", d.Plan)
	}
}
