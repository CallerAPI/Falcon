package voice

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMergeTurnsOrdersSpeakersAndJoinsRuns(t *testing.T) {
	caller := []Segment{{Start: 0.2, End: 1.5, Text: "Hello, this is Mark"}, {Start: 1.8, End: 3.0, Text: "from your bank."}, {Start: 9, End: 10, Text: "Thanks for watching!"}}
	callee := []Segment{{Start: 3.4, End: 4.2, Text: "Which bank?"}, {Start: 6.0, End: 6.5, Text: " "}}
	turns := MergeTurns(caller, callee)
	if len(turns) != 2 {
		t.Fatalf("turns %+v", turns)
	}
	if turns[0].Speaker != SpeakerCaller || turns[0].Text != "Hello, this is Mark from your bank." || turns[0].End != 3.0 {
		t.Fatalf("first turn %+v", turns[0])
	}
	if turns[1].Speaker != SpeakerCallee || turns[1].Text != "Which bank?" {
		t.Fatalf("second turn %+v", turns[1])
	}
	if got := LabeledTranscript(turns); got != "Caller: Hello, this is Mark from your bank.\nCallee: Which bank?" {
		t.Fatalf("labeled %q", got)
	}
}

func stereoWAV(seconds int) []byte {
	n := 8000 * seconds
	left, right := make([]int16, n), make([]int16, n)
	for i := range left {
		left[i], right[i] = 1000, -1000
	}
	return encodeWAV(Clip{Rate: 8000, Channels: [][]int16{left, right}})
}

func TestSplitStereoKeepsChannelsApart(t *testing.T) {
	l, r, ok := SplitStereo(stereoWAV(1))
	if !ok {
		t.Fatal("stereo not split")
	}
	lc, _ := DecodeWAV(l)
	rc, _ := DecodeWAV(r)
	if len(lc.Channels) != 1 || lc.Channels[0][10] != 1000 || rc.Channels[0][10] != -1000 {
		t.Fatal("channels mixed")
	}
	mono := encodeWAV(Clip{Rate: 8000, Channels: [][]int16{make([]int16, 800)}})
	if _, _, ok := SplitStereo(mono); ok {
		t.Fatal("mono split as stereo")
	}
}

func TestOpenAICompatTranscribesEachChannel(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/audio/transcriptions"):
			_ = r.ParseMultipartForm(1 << 20)
			if r.FormValue("response_format") != "verbose_json" {
				t.Errorf("format %q", r.FormValue("response_format"))
			}
			mu.Lock()
			calls++
			n := calls
			mu.Unlock()
			if n == 1 {
				_, _ = io.WriteString(w, `{"text":"Your car warranty expires","segments":[{"start":0.5,"end":2.0,"text":"Your car warranty expires","no_speech_prob":0.01}]}`)
				return
			}
			_, _ = io.WriteString(w, `{"text":"Who is this?","segments":[{"start":2.4,"end":3.0,"text":"Who is this?","no_speech_prob":0.02}]}`)
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "Caller: Your car warranty expires") || !strings.Contains(string(body), "Callee: Who is this?") {
				t.Errorf("classifier did not get the labeled transcript: %s", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"content": `{"category":"Warranties & Protection Plans","score":0.92,"summary":"Car warranty robocall"}`}}}})
		}
	}))
	defer srv.Close()
	p := &OpenAICompat{STTBaseURL: srv.URL, ChatBaseURL: srv.URL, STTModel: "whisper-1", ChatModel: "m"}
	v, err := p.Analyse(context.Background(), stereoWAV(3), Meta{})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(v.Turns) != 2 || v.Turns[0].Speaker != SpeakerCaller || v.Turns[1].Speaker != SpeakerCallee {
		t.Fatalf("calls %d turns %+v", calls, v.Turns)
	}
	if v.Category != "Warranties & Protection Plans" || v.Score < 0.9 {
		t.Fatalf("verdict %+v", v)
	}
}

func TestCallerAPISendsStereoWholeAndReadsTurns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			t.Fatal(err)
		}
		fields := map[string]string{}
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(part)
			if part.FormName() != "audio" {
				fields[part.FormName()] = string(b)
			} else if c, err := DecodeWAV(b); err != nil || len(c.Channels) != 2 {
				t.Errorf("audio is not stereo: %v", err)
			}
			_ = part.Close()
		}
		if fields["split_channels"] != "true" || fields["call_id"] != "abc" {
			t.Errorf("fields %v", fields)
		}
		_, _ = io.WriteString(w, `{"transcript":"x","turns":[{"speaker":"caller","start":0.4,"end":1.2,"text":"This is the IRS."},{"speaker":"callee","start":1.6,"end":2.0,"text":"No it is not."},{"speaker":"robot","start":3,"end":4,"text":"drop me"}],"verdict":{"score":0.88,"category":"Tax Collection","summary":"IRS scam"}}`)
	}))
	defer srv.Close()
	p := &CallerAPI{BaseURL: srv.URL, APIKey: "k"}
	v, err := p.Analyse(context.Background(), stereoWAV(2), Meta{CallID: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Turns) != 2 || v.Transcript != "Caller: This is the IRS.\nCallee: No it is not." || v.Category != "Tax Collection" {
		t.Fatalf("verdict %+v", v)
	}
}

// A long call goes in pieces. Only the first piece names the call, so
// CallerAPI bills every piece for its own minutes.
func TestCallerAPINamesTheCallOnTheFirstPieceOnly(t *testing.T) {
	var calls []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			t.Fatal(err)
		}
		fields := map[string]string{}
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(part)
			if part.FormName() != "audio" {
				fields[part.FormName()] = string(b)
			}
			_ = part.Close()
		}
		calls = append(calls, fields)
		_, _ = io.WriteString(w, `{"turns":[{"speaker":"caller","start":1,"end":2,"text":"Hello."}],"verdict":{"score":0.1,"category":"none"}}`)
	}))
	defer srv.Close()
	p := &CallerAPI{BaseURL: srv.URL, APIKey: "k"}
	v, err := p.Analyse(context.Background(), stereoWAV(StereoPieceSeconds+2), Meta{CallID: "abc", Report: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0]["call_id"] != "abc" || calls[1]["call_id"] != "" {
		t.Fatalf("call_id per piece %v", calls)
	}
	if calls[0]["report"] != "" || calls[1]["report"] != "true" {
		t.Fatalf("report per piece %v", calls)
	}
	if len(v.Turns) != 2 || v.Turns[1].Start != StereoPieceSeconds+1 {
		t.Fatalf("second piece is not on the call timeline %+v", v.Turns)
	}
}
