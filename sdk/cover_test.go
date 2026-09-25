package sdk

import (
	"strings"
	"testing"
)

func TestAsMapKeepsKnownFieldsAndDropsEmpty(t *testing.T) {
	got := (Input{
		From: "+1", SourceIP: "203.0.113.9", UserAgent: "ua", CallID: "c",
		Attest: "A", Verstat: "pass", SignerSPC: "1", SignerName: "n", Provider: "p",
		Fingerprint: "f", Direction: "inbound", Method: "INVITE", Action: "allow",
		Score: "10", ReasonCodes: "a,b",
	}).AsMap()
	if len(got) != len(Fields) {
		t.Fatalf("fields %d %+v", len(got), got)
	}
	if (Input{}).AsMap()["from"] != "" && len((Input{}).AsMap()) != 0 {
		t.Fatal("empty input leaked")
	}
	if len((Input{}).AsMap()) != 0 {
		t.Fatal("empty input kept keys")
	}
}

func TestKnownRejectsCalledParty(t *testing.T) {
	if Known("to") || Known("raw_sip") || Known("") {
		t.Fatal("unknown field accepted")
	}
	if !Known("from") {
		t.Fatal("from refused")
	}
}

func TestCleanQueryStripsMarkupAndCapsLength(t *testing.T) {
	if CleanQuery("  +1415  ") != "+1415" {
		t.Fatal("trim")
	}
	if CleanQuery("a<b>") != "" || CleanQuery("a\nb") != "" {
		t.Fatal("markup kept")
	}
	long := strings.Repeat("1", 80)
	if len(CleanQuery(long)) != 64 {
		t.Fatal("cap")
	}
}

func TestFrameOrigin(t *testing.T) {
	if FrameOrigin("https://api.callerapi.com/api") != "https://api.callerapi.com" {
		t.Fatal("https origin")
	}
	if FrameOrigin("http://127.0.0.1:18099") != "http://127.0.0.1:18099" {
		t.Fatal("http origin")
	}
	if FrameOrigin("https://ex ample.com") != "" && strings.Contains(FrameOrigin("https://a;b"), ";") {
		t.Fatal("odd host")
	}
	for _, raw := range []string{"", "not a url", "javascript:alert(1)", "https://user:pass@api.callerapi.com", "ftp://api.callerapi.com"} {
		if FrameOrigin(raw) != "" {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestSameOriginRejectsBadBaseAndSchemeMismatch(t *testing.T) {
	if SameOrigin("ftp://api.callerapi.com", "https://api.callerapi.com/api/falcon/v1/plugins/a/frame") {
		t.Fatal("bad base")
	}
	if SameOrigin("https://api.callerapi.com", "http://api.callerapi.com/api/falcon/v1/plugins/a/frame") {
		t.Fatal("scheme mismatch")
	}
	if SameOrigin("https://user:pass@api.callerapi.com", "https://api.callerapi.com/api/falcon/v1/plugins/a/frame") {
		t.Fatal("userinfo base")
	}
}

func TestSanitizePanel(t *testing.T) {
	cols := []Column{{Key: strings.Repeat("n", 33), Label: "Long"}, {Key: "bad key", Label: "No"}, {Key: "ok_1", Label: "Ok"}}
	rows := make([]map[string]string, 0, 60)
	stats := make([]Stat, 0, 10)
	for i := 0; i < 10; i++ {
		cols = append(cols, Column{Key: "number", Label: "Number\nline"})
		stats = append(stats, Stat{Label: strings.Repeat("L", 50), Value: strings.Repeat("V", 50)})
	}
	for i := 0; i < 60; i++ {
		rows = append(rows, map[string]string{"number": strings.Repeat("1", 100), "other": "x"})
	}
	native := SanitizePanel(Panel{
		Title: "  Hello\nthere  ", Surface: "nope", Widget: "chart",
		Columns: cols, Rows: rows, Stats: stats,
	})
	if native.Surface != "" || native.Widget != "table" || len(native.Columns) == 0 || len(native.Rows) != 50 || len(native.Stats) != 8 {
		t.Fatalf("native %+v", native)
	}
	if strings.Contains(native.Title, "\n") || len(native.Columns[0].Label) > 40 || len(native.Rows[0]["number"]) > 80 {
		t.Fatal("clip")
	}
	frame := SanitizePanel(Panel{Surface: "iframe", Widget: "stats", Import: true, FrameURL: " https://api.example/api/falcon/v1/plugins/a/frame "})
	if frame.FrameURL == "" || len(frame.Columns) != 0 || frame.Import {
		t.Fatalf("frame %+v", frame)
	}
	kept := SanitizePanel(Panel{Surface: "native", Widget: "table", Import: true, Columns: []Column{{Key: "number", Label: "Number"}}})
	if !kept.Import {
		t.Fatal("import")
	}
}
