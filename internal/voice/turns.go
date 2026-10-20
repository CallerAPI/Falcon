package voice

import (
	"sort"
	"strings"
)

// Speakers on a bridged call. The caller is the left channel of the
// recording, the callee the right.
const (
	SpeakerCaller = "caller"
	SpeakerCallee = "callee"
)

// Segment is text a speech model heard in one channel, with times in
// seconds from the start of the recording.
type Segment struct {
	Start float64 `json:"start"`
	End   float64 `json:"end"`
	Text  string  `json:"text"`
}

// Turn is one stretch of one speaker.
type Turn struct {
	Speaker string  `json:"speaker"`
	Start   float64 `json:"start"`
	End     float64 `json:"end"`
	Text    string  `json:"text"`
}

// mergeGap joins two segments of the same speaker into one turn.
const mergeGap = 1.2

// MergeTurns orders both channels' segments on one timeline and joins
// back-to-back segments of the same speaker.
func MergeTurns(caller, callee []Segment) []Turn {
	var all []Turn
	for _, s := range caller {
		if t := strings.TrimSpace(s.Text); t != "" && !hallucination(t) {
			all = append(all, Turn{Speaker: SpeakerCaller, Start: s.Start, End: s.End, Text: t})
		}
	}
	for _, s := range callee {
		if t := strings.TrimSpace(s.Text); t != "" && !hallucination(t) {
			all = append(all, Turn{Speaker: SpeakerCallee, Start: s.Start, End: s.End, Text: t})
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Start < all[j].Start })
	var out []Turn
	for _, t := range all {
		if n := len(out); n > 0 && out[n-1].Speaker == t.Speaker && t.Start-out[n-1].End <= mergeGap {
			out[n-1].Text += " " + t.Text
			if t.End > out[n-1].End {
				out[n-1].End = t.End
			}
			continue
		}
		out = append(out, t)
	}
	return out
}

// LabeledTranscript writes turns as "Caller: ..." and "Callee: ..." lines.
// The classifier reads who said what from it.
func LabeledTranscript(turns []Turn) string {
	var b strings.Builder
	for i, t := range turns {
		if i > 0 {
			b.WriteByte('\n')
		}
		if t.Speaker == SpeakerCallee {
			b.WriteString("Callee: ")
		} else {
			b.WriteString("Caller: ")
		}
		b.WriteString(t.Text)
	}
	return b.String()
}

// hallucination drops the stock phrases speech models emit for noise or
// silence when they stand alone.
func hallucination(text string) bool {
	t := strings.ToLower(strings.Trim(strings.TrimSpace(text), ".!?, "))
	switch t {
	case "", "thanks for watching", "thank you for watching", "please subscribe", "you":
		return true
	}
	return false
}
