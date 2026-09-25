package sdk

import "testing"

func TestSameOriginAllowsOnlyThePluginPrefix(t *testing.T) {
	base := "https://api.callerapi.com"
	if !SameOrigin(base, "https://api.callerapi.com/api/falcon/v1/plugins/watch/frame?ticket=1") {
		t.Fatal("same host frame refused")
	}
	for _, raw := range []string{
		"https://evil.example/api/falcon/v1/plugins/watch/frame",
		"https://api.callerapi.com/dashboard",
		"javascript:alert(1)",
		"https://user:pass@api.callerapi.com/api/falcon/v1/plugins/watch/frame",
	} {
		if SameOrigin(base, raw) {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestSelectDropsUnknownAndCalledParty(t *testing.T) {
	all := map[string]string{
		"from": "+14155550100", "to": "+15551212", "raw_sip": "INVITE",
		"source_ip": "203.0.113.9", "not_a_field": "x",
	}
	got := Select(all, []string{"from", "to", "raw_sip", "not_a_field", "source_ip"})
	if got["from"] != "+14155550100" || got["source_ip"] != "203.0.113.9" {
		t.Fatalf("kept %+v", got)
	}
	if _, ok := got["to"]; ok {
		t.Fatal("called number leaked")
	}
	if _, ok := got["raw_sip"]; ok {
		t.Fatal("raw sip leaked")
	}
	if _, ok := got["not_a_field"]; ok {
		t.Fatal("unknown field leaked")
	}
}
