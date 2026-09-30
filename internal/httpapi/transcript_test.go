package httpapi

import "testing"

func TestReadTranscript(t *testing.T) {
	line := readTranscript([]byte(`{"data":{"callid":"abc","cli":"+1512","dest_number":"+1915","transcript":"pay with gift cards","final":true}}`))
	if line.CallID != "abc" || line.From != "+1512" || line.To != "+1915" || line.Text != "pay with gift cards" || !line.Final {
		t.Fatalf("%+v", line)
	}
	plain := readTranscript([]byte(`not json`))
	if plain.Text != "not json" {
		t.Fatalf("%+v", plain)
	}
	empty := readTranscript([]byte(`{"status":"ok"}`))
	if empty.Text != "" || empty.Raw == "" {
		t.Fatalf("%+v", empty)
	}
}

func TestTranscriptScoreDebounce(t *testing.T) {
	var marks transcriptScore
	if !marks.due("c1", "hello gift cards", true) {
		t.Fatal("final")
	}
	if marks.due("c1", "hello gift cards", false) {
		t.Fatal("unchanged partial")
	}
}
