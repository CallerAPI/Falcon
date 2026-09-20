package score

import (
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/sipmsg"
)

func cleanSnapshot(t *testing.T) sipmsg.Snapshot {
	t.Helper()
	eng := testEngine()
	raw := invite("+14155550100", "+15551212", "Asterisk PBX 20", passport("A", "14155550100", eng.Now().Add(-10*time.Second).Unix()), "70")
	m, err := sipmsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return sipmsg.SnapshotFrom(m, "203.0.113.9")
}

func TestNetworkReputationIsCorroborationByDefault(t *testing.T) {
	snap := cleanSnapshot(t)

	// One install's opinion is ignored.
	res := testEngine().Score(snap, Enrichment{Network: &Network{SignerScore: 95, SignerInstalls: 1}})
	if hasCode(res, "network_signer") {
		t.Fatal("a single install must not move the score")
	}

	// A pattern across installs flags or challenges, never rejects alone.
	res = testEngine().Score(snap, Enrichment{Network: &Network{
		SignerScore: 95, SignerInstalls: 12, FingerprintScore: 90, FingerprintInstalls: 9,
	}})
	if !hasCode(res, "network_signer") || !hasCode(res, "network_fingerprint") {
		t.Fatalf("expected both network reasons: %+v", res.Reasons)
	}
	if res.Action == ActionReject {
		t.Fatalf("reputation alone rejected: score %d", res.RiskScore)
	}
	if res.RiskScore < 60 {
		t.Fatalf("strong network signal scored only %d", res.RiskScore)
	}
	if res.Signals.NetworkSignerScore != 95 || res.Signals.NetworkFingerprintScore != 90 {
		t.Fatalf("signals: %+v", res.Signals)
	}
}

func TestNetworkReputationEnforceRejectsStrongSigner(t *testing.T) {
	snap := cleanSnapshot(t)
	res := testEngine().Score(snap, Enrichment{Network: &Network{SignerScore: 92, SignerInstalls: 6, Enforce: true}})
	if res.Action != ActionReject || res.Headers["X-Falcon-Block"] != "network_signer" {
		t.Fatalf("enforce: action %s block %q", res.Action, res.Headers["X-Falcon-Block"])
	}
	// Enforce still needs breadth: five installs and a score of ninety.
	res = testEngine().Score(snap, Enrichment{Network: &Network{SignerScore: 92, SignerInstalls: 4, Enforce: true}})
	if res.Action == ActionReject {
		t.Fatal("enforce rejected on four installs")
	}
}
