package lists

import (
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	r, err := Normalize(Rule{Kind: Deny, Subject: Number, Value: " (415) 555-0100 "})
	if err != nil || r.Value != "+4155550100" {
		t.Fatalf("number: %+v %v", r, err)
	}
	r, err = Normalize(Rule{Kind: Allow, Subject: IP, Value: "203.0.113.77"})
	if err != nil || r.Value != "203.0.113.77/32" {
		t.Fatalf("ip: %+v %v", r, err)
	}
	r, err = Normalize(Rule{Kind: Allow, Subject: IP, Value: "203.0.113.77/24"})
	if err != nil || r.Value != "203.0.113.0/24" {
		t.Fatalf("cidr masked: %+v %v", r, err)
	}
	r, err = Normalize(Rule{Kind: Deny, Subject: SPC, Value: " 123a "})
	if err != nil || r.Value != "123A" {
		t.Fatalf("spc: %+v %v", r, err)
	}
	if _, err := Normalize(Rule{Kind: "maybe", Subject: Number, Value: "1"}); err == nil {
		t.Fatal("bad kind accepted")
	}
	if _, err := Normalize(Rule{Kind: Deny, Subject: IP, Value: "not-an-ip"}); err == nil {
		t.Fatal("bad ip accepted")
	}
	r, err = Normalize(Rule{Kind: International, Subject: IP, Value: "203.0.113.9"})
	if err != nil || r.Value != "203.0.113.9/32" {
		t.Fatalf("international: %+v %v", r, err)
	}
	if _, err := Normalize(Rule{Kind: International, Subject: Number, Value: "+447700900123"}); err == nil {
		t.Fatal("international number accepted")
	}
	r, err = Normalize(Rule{Kind: Exempt, Subject: SPC, Value: " 12ab "})
	if err != nil || r.Value != "12AB" {
		t.Fatalf("exempt spc: %+v %v", r, err)
	}
	if _, err := Normalize(Rule{Kind: Exempt, Subject: Number, Value: "+447700900123"}); err == nil {
		t.Fatal("exempt number accepted")
	}
}

func TestMatchDenyBeatsAllowAndLongestPrefix(t *testing.T) {
	now := time.Now()
	idx := NewIndex([]Rule{
		{ID: 1, Kind: Allow, Subject: IP, Value: "203.0.113.0/24"},
		{ID: 2, Kind: Deny, Subject: IP, Value: "203.0.113.128/25"},
		{ID: 3, Kind: Allow, Subject: Number, Value: "+14155550100"},
		{ID: 4, Kind: Deny, Subject: SPC, Value: "666A"},
		{ID: 5, Kind: Allow, Subject: Number, Value: "+15005550000", ExpiresAt: now.Add(-time.Minute)},
	}, now)
	if idx.Count() != 4 {
		t.Fatalf("expired rule counted: %d", idx.Count())
	}
	h, ok := idx.Match("+19999999999", "203.0.113.5", "")
	if !ok || h.ID != 1 {
		t.Fatalf("/24 allow: %+v %v", h, ok)
	}
	h, ok = idx.Match("+19999999999", "203.0.113.200", "")
	if !ok || h.ID != 2 {
		t.Fatalf("/25 deny must win: %+v %v", h, ok)
	}
	h, ok = idx.Match("14155550100", "198.51.100.1", "")
	if !ok || h.ID != 3 {
		t.Fatalf("number allow without plus: %+v %v", h, ok)
	}
	h, ok = idx.Match("+14155550100", "198.51.100.1", "666a")
	if !ok || h.ID != 4 {
		t.Fatalf("spc deny must beat number allow: %+v %v", h, ok)
	}
	if _, ok := idx.Match("+15005550000", "192.0.2.1", ""); ok {
		t.Fatal("expired rule matched")
	}
	if _, ok := idx.Match("", "", ""); ok {
		t.Fatal("empty input matched")
	}
}

func TestInternationalAndExempt(t *testing.T) {
	now := time.Now()
	rules, err := PeerRules("203.0.113.0/24, 198.51.100.8", "192.0.2.10", "99ab")
	if err != nil {
		t.Fatal(err)
	}
	rules = append(rules, Rule{ID: 9, Kind: Exempt, Subject: IP, Value: "203.0.113.50/32"})
	idx := NewIndex(rules, now)
	if !idx.International("203.0.113.9") || !idx.International("198.51.100.8") {
		t.Fatal("international peer missed")
	}
	if idx.International("192.0.2.10") || idx.International("") {
		t.Fatal("unlisted peer marked international")
	}
	if !idx.Exempt("192.0.2.10", "") || !idx.Exempt("203.0.113.50", "") || !idx.Exempt("198.51.100.1", "99AB") {
		t.Fatal("exemption missed")
	}
	if idx.Exempt("203.0.113.9", "0000") {
		t.Fatal("international peer was exempt")
	}
	if _, ok := idx.Match("+447700900123", "203.0.113.9", "99AB"); ok {
		t.Fatal("international and exempt rules must not allow or deny")
	}
	if _, err := PeerRules("not-an-ip", "", ""); err == nil {
		t.Fatal("bad peer accepted")
	}
}
