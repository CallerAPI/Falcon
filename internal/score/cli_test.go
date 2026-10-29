package score

import (
	"strings"
	"testing"

	"github.com/callerapi/falcon/internal/sipmsg"
)

const ukMobile = "+447700900123"

func TestWithheldCallIsNotAPAIMismatch(t *testing.T) {
	raw := "INVITE sip:+14155550100@ex SIP/2.0\n" +
		"From: \"Anonymous\" <sip:anonymous@anonymous.invalid>;tag=1\n" +
		"To: <sip:+14155550100@ex>\n" +
		"P-Asserted-Identity: <sip:" + ukMobile + "@ex>\n" +
		"Privacy: id\n" +
		"Call-ID: x\nUser-Agent: X\nMax-Forwards: 70\n" +
		"Content-Type: application/sdp\n\nv=0\n"
	m, err := sipmsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	snap := sipmsg.SnapshotFrom(m, "203.0.113.9")
	res := testEngine().Score(snap, Enrichment{})
	if hasCode(res, "from_pai_mismatch") {
		t.Fatalf("withheld call scored as a mismatch: %+v", res.Reasons)
	}
	if hasCode(res, ReasonUKMobileFromAbroad) {
		t.Fatal("an already withheld call is not a presentation number")
	}
	if res.Signals.From != "anonymous" {
		t.Fatalf("from shown as %q", res.Signals.From)
	}
	if ReputationNumber(snap) != ukMobile {
		t.Fatalf("reputation number %q", ReputationNumber(snap))
	}

	open := strings.Replace(raw, "Privacy: id\n", "", 1)
	m, _ = sipmsg.Parse(open)
	res = testEngine().Score(sipmsg.SnapshotFrom(m, "203.0.113.9"), Enrichment{})
	if !hasCode(res, "from_pai_mismatch") {
		t.Fatalf("anonymous From without Privacy id must still mismatch: %+v", res.Reasons)
	}
}

func TestUKMobileFromAbroadInformsOnly(t *testing.T) {
	raw := "INVITE sip:+14155550100@ex SIP/2.0\n" +
		"From: <sip:" + ukMobile + "@ex>;tag=1\n" +
		"To: <sip:+14155550100@ex>\n" +
		"Call-ID: x\nUser-Agent: desk\nMax-Forwards: 70\n" +
		"Content-Type: application/sdp\n\nv=0\n"
	m, err := sipmsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	snap := sipmsg.SnapshotFrom(m, "")
	base := testEngine().Score(snap, Enrichment{})
	hit := testEngine().Score(snap, Enrichment{International: true})
	if hasCode(base, ReasonUKMobileFromAbroad) {
		t.Fatal("domestic peer was marked")
	}
	if !hasCode(hit, ReasonUKMobileFromAbroad) {
		t.Fatalf("missing reason: %+v", hit.Reasons)
	}
	for _, r := range hit.Reasons {
		if r.Code == ReasonUKMobileFromAbroad && r.Weight != 0 {
			t.Fatalf("weight %d", r.Weight)
		}
	}
	if hit.RiskScore != base.RiskScore || hit.Action != base.Action {
		t.Fatalf("reason changed the decision: base %s/%d hit %s/%d", base.Action, base.RiskScore, hit.Action, hit.RiskScore)
	}
	if hit.Headers[HeaderCLIWithhold] != "" {
		t.Fatalf("header set while enforce is off: %v", hit.Headers)
	}
	enf := testEngine().Score(snap, Enrichment{International: true, CLIEnforce: true})
	if enf.Headers[HeaderCLIWithhold] != "1" || enf.RiskScore != base.RiskScore {
		t.Fatalf("enforce header %q score %d", enf.Headers[HeaderCLIWithhold], enf.RiskScore)
	}
	exempt := testEngine().Score(snap, Enrichment{International: true, CLIExempt: true, CLIEnforce: true})
	if hasCode(exempt, ReasonUKMobileFromAbroad) || exempt.Headers[HeaderCLIWithhold] != "" {
		t.Fatalf("exempt peer was withheld: %+v %v", exempt.Reasons, exempt.Headers)
	}
}

func TestPresentationUsesPAIOnlyWhenPrivacyIsNone(t *testing.T) {
	raw := "INVITE sip:+14155550100@ex SIP/2.0\n" +
		"From: <sip:+14155550100@ex>;tag=1\n" +
		"To: <sip:+13125550100@ex>\n" +
		"P-Asserted-Identity: <sip:" + ukMobile + "@ex>\n" +
		"Privacy: none\n" +
		"Diversion: <sip:" + ukMobile + "@ex>\n" +
		"History-Info: <sip:" + ukMobile + "@ex>;index=1\n" +
		"Call-ID: x\nUser-Agent: desk\nMax-Forwards: 70\n" +
		"Content-Type: application/sdp\n\nv=0\n"
	m, err := sipmsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	snap := sipmsg.SnapshotFrom(m, "")
	if PresentationNumber(snap) != ukMobile {
		t.Fatalf("presentation %q", PresentationNumber(snap))
	}
	res := testEngine().Score(snap, Enrichment{International: true})
	if !hasCode(res, ReasonUKMobileFromAbroad) {
		t.Fatalf("PAI presentation missed: %+v", res.Reasons)
	}

	shown := strings.Replace(raw, "Privacy: none\n", "Privacy: id\n", 1)
	m, _ = sipmsg.Parse(shown)
	snap = sipmsg.SnapshotFrom(m, "")
	if PresentationNumber(snap) != "+14155550100" {
		t.Fatalf("privacy id must keep From, got %q", PresentationNumber(snap))
	}
	res = testEngine().Score(snap, Enrichment{International: true})
	if hasCode(res, ReasonUKMobileFromAbroad) {
		t.Fatal("Diversion or History-Info was treated as the caller ID")
	}
}

func TestReputationNumberStaysOnFromUntilWithheld(t *testing.T) {
	snap := sipmsg.Snapshot{FromUser: ukMobile, PAIUser: "+14155550100", Privacy: "none"}
	if ReputationNumber(snap) != ukMobile {
		t.Fatalf("got %q", ReputationNumber(snap))
	}
	snap.FromUser = "anonymous"
	snap.Privacy = "id"
	snap.PAIUser = ukMobile
	if !WithheldIdentity(snap) || ReputationNumber(snap) != ukMobile {
		t.Fatalf("withheld reputation %q", ReputationNumber(snap))
	}
}
