package bridge

import (
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
)

func TestApplyCLIWithholdKeepsPAI(t *testing.T) {
	req := sip.NewRequest(sip.INVITE, sip.Uri{Scheme: "sip", User: "+14155550100", Host: "switch.example"})
	from := &sip.FromHeader{
		DisplayName: "Alice",
		Address:     sip.Uri{Scheme: "sip", User: "+447700900123", Host: "gw.example"},
		Params:      sip.NewParams(),
	}
	from.Params.Add("tag", "t1")
	req.AppendHeader(from)
	req.AppendHeader(sip.NewHeader("P-Asserted-Identity", "<sip:+447700900123@gw.example>"))
	req.AppendHeader(sip.NewHeader("Privacy", "none"))

	applyCLIWithhold(req)

	got := req.From()
	if got == nil || got.Address.User != "anonymous" || got.Address.Host != "anonymous.invalid" || got.DisplayName != "Anonymous" {
		t.Fatalf("from = %+v", got)
	}
	if tag, ok := got.Params.Get("tag"); !ok || tag != "t1" {
		t.Fatalf("tag = %q ok=%v", tag, ok)
	}
	pai := req.GetHeader("P-Asserted-Identity")
	if pai == nil || !strings.Contains(pai.Value(), "+447700900123") {
		t.Fatalf("pai = %v", pai)
	}
	priv := req.GetHeaders("Privacy")
	if len(priv) != 1 || priv[0].Value() != "id" {
		t.Fatalf("privacy = %#v", priv)
	}
	if strings.Contains(req.From().String(), "+447700900123") {
		t.Fatalf("from still shows the number: %s", req.From().String())
	}
}
