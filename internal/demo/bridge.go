package demo

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

// RecordingsDir is where the demo keeps its call recordings.
func RecordingsDir(dir string) string { return filepath.Join(Dir(dir), "recordings") }

type demoTurn struct {
	speaker    string
	start, end float64
	text       string
}

type demoCall struct {
	from, to, category, summary string
	score                       float64
	turns                       []demoTurn
}

var scamCalls = []demoCall{
	{from: "+18885550142", to: "+14155550100", category: "Warranties & Protection Plans", score: 0.94, summary: "Robocall pushing an extended car warranty.", turns: []demoTurn{
		{"caller", 0.6, 5.2, "Hi, we have been trying to reach you about your car's extended warranty. This is your final courtesy call."},
		{"callee", 5.8, 6.9, "Who is this?"},
		{"caller", 7.3, 11.6, "Press one now to speak with a warranty specialist before your coverage expires."},
	}},
	{from: "+12025550177", to: "+12125550188", category: "Tax Collection", score: 0.97, summary: "Caller claims a tax warrant and asks for gift cards.", turns: []demoTurn{
		{"caller", 0.4, 5.0, "This is officer Daniel Brooks from the tax department. There is a warrant on your social security number."},
		{"callee", 5.5, 7.0, "What? I paid my taxes."},
		{"caller", 7.4, 12.2, "To stop the arrest today you must pay the balance with gift cards. Stay on the line."},
	}},
	{from: "+16465550123", to: "+13125550120", category: "Computer & Technical Support", score: 0.91, summary: "Fake support desk asks the callee to open a website.", turns: []demoTurn{
		{"caller", 0.5, 4.6, "Hello, I am calling from the computer support team. Your computer is sending us error messages."},
		{"callee", 5.0, 6.2, "My computer is fine."},
		{"caller", 6.7, 10.9, "Please go to your computer now and open the website I give you so we can fix it."},
	}},
	{from: "+18445550160", to: "+16175550144", category: "Bank/Credit Card Company Imposter", score: 0.93, summary: "Automated bank alert that dictates a callback number.", turns: []demoTurn{
		{"caller", 0.3, 4.4, "This is an automated alert from your bank's security department. A charge of 899 dollars was detected."},
		{"callee", 4.9, 6.0, "I did not make that."},
		{"caller", 6.4, 10.1, "Press one, or call us back at 888 555 0142 to dispute the charge."},
	}},
	{from: "+14155550821", to: "+17205550102", category: "none", score: 0.04, summary: "Appointment reminder from a clinic.", turns: []demoTurn{
		{"caller", 0.5, 3.9, "Hi, this is the clinic confirming your appointment tomorrow at ten."},
		{"callee", 4.3, 6.1, "Yes, I will be there. Thank you."},
	}},
}

type fasCall struct {
	route, kind, action string
	falseMS, talkMS     int
}

var fasCalls = []fasCall{
	{"Vendor Bravo", "ringback", "observed", 14200, 9000},
	{"Vendor Bravo", "ringback", "observed", 9800, 22000},
	{"Vendor Bravo", "ringback", "held", 17400, 31000},
	{"Vendor Bravo", "dead_air", "observed", 6100, 0},
	{"Vendor Bravo", "ringback", "failed", 60000, 0},
	{"Vendor Bravo", "busy", "observed", 4300, 0},
	{"Vendor Bravo", "", "", 0, 48000},
	{"Vendor Bravo", "", "", 0, 125000},
	{"Vendor Atlas", "sit", "observed", 5200, 0},
	{"Vendor Atlas", "", "", 0, 64000},
	{"Vendor Atlas", "", "", 0, 210000},
	{"Vendor Atlas", "", "", 0, 39000},
	{"Vendor Atlas", "", "", 0, 92000},
	{"Vendor Atlas", "", "", 0, 17000},
}

// bridgeRows is what the SIP bridge would have produced: vendor routes,
// bridged calls with false answers, recorded scam calls with turns, and a
// fan-out dialer. Routes and recordings are written now. The calls come
// back as rows so the caller inserts them in time order with the rest.
func bridgeRows(ctx context.Context, db *store.SQLite, dir string, end time.Time) ([]row, error) {
	for _, r := range []store.Route{
		{Prefix: "9901", Label: "Vendor Atlas", Strip: true, Carry: store.CarryAll},
		{Prefix: "9902", Label: "Vendor Bravo", Strip: true, Carry: store.CarryAll},
	} {
		if _, err := db.PutRoute(ctx, r); err != nil {
			return nil, err
		}
	}
	recDir := RecordingsDir(dir)
	if err := os.MkdirAll(filepath.Join(recDir, "demo"), 0o750); err != nil {
		return nil, err
	}
	var rows []row
	rng := rand.New(rand.NewSource(7))
	for i, fc := range fasCalls {
		rows = append(rows, fasRow(i, fc, end, rng))
	}
	for i, sc := range scamCalls {
		r, err := voiceRow(i, sc, end, recDir)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	for i := 0; i < 64; i++ {
		rows = append(rows, row{ev: store.Event{ReceivedAt: end.Add(-time.Duration(i*4) * time.Minute), Action: score.ActionFlag, RiskScore: 48, SourceIP: "203.0.113.20",
			From: "+19295550133", To: fmt.Sprintf("+1718555%04d", 1000+i), CallID: fmt.Sprintf("demo-fan-%d", i), UserAgent: "Harborline-SBC/1.9",
			Direction: "inbound", Switch: "sip/10.0.0.5", LatencyUS: int64(1800 + i*7),
			Reasons: []score.Reason{{Code: "caller_fanout", Weight: 25, Detail: fmt.Sprintf("Called %d different numbers in the last hour", 30+i/2)}, {Code: "sequential_dialing", Weight: 20, Detail: "Five numbers in a row, one apart"}}}})
	}
	return rows, nil
}

// fasRow is one bridged call to a vendor route, with or without a false answer.
func fasRow(i int, fc fasCall, end time.Time, rng *rand.Rand) row {
	at := end.Add(-time.Duration(50+i*80) * time.Minute)
	callID := fmt.Sprintf("demo-bridge-%d", i)
	ev := store.Event{ReceivedAt: at, Action: score.ActionChallenge, RiskScore: 62, SourceIP: "198.51.100.40",
		From: fmt.Sprintf("+1312555%04d", 2000+i), To: fmt.Sprintf("+1415555%04d", 3000+i), CallID: callID,
		UserAgent: "Lakeshore-GW/2.0", Direction: "inbound", Switch: "sip/10.0.0.5", LatencyUS: int64(2600 + rng.Intn(900)),
		Reasons: []score.Reason{{Code: "missing_identity", Weight: 15, Detail: "Identity header is missing"}, {Code: "caller_short_calls", Weight: 30, Detail: "Answered calls average 6 s"}}}
	answer := 2200 + rng.Intn(1500)
	return row{ev: ev, after: func(ctx context.Context, db *store.SQLite, id int64) error {
		m := store.MediaCall{EventID: id, CallID: callID, LegBCallID: callID + "-b", Route: fc.route, Carry: "route", From: ev.From, To: ev.To,
			StartedAt: at, RingMS: answer - 1400, AnswerMS: answer, Codec: "PCMU/8000", Status: 200, EndedBy: "caller",
			FAS: fc.kind, FASMS: fc.falseMS, FASAction: fc.action, PacketsA: 900, PacketsB: 870}
		m.ConnectMS = answer
		switch fc.action {
		case "held":
			m.ConnectMS = answer + fc.falseMS
		case "failed":
			m.ConnectMS, m.Status, m.EndedBy = 0, 480, "falcon"
		}
		m.EndMS = answer + fc.falseMS + fc.talkMS
		if fc.kind != "" {
			detail, _ := json.Marshal(map[string]any{"answer_ms": answer, "tone_after_answer_ms": fc.falseMS, "callee_speech_ms": fc.talkMS / 3,
				"bursts": []map[string]int{{"start_ms": answer, "end_ms": answer + fc.falseMS}}})
			m.FASDetail = detail
		}
		mid, err := db.InsertMediaCall(ctx, m)
		if err != nil {
			return err
		}
		m.ID = mid
		if err := db.UpdateMediaCall(ctx, m); err != nil {
			return err
		}
		if fc.kind != "" {
			_ = db.NoteReason(ctx, id, score.Reason{Code: "fas_" + fc.kind, Category: "fas",
				Detail: fmt.Sprintf("%.1f s of billed time after the answer was not a conversation", float64(fc.falseMS)/1000)})
		}
		_, err = db.SetOutcome(ctx, callID, store.Outcome{Answered: m.ConnectMS > 0, DurationS: fc.talkMS / 1000, HangupCause: "bridge_" + m.EndedBy})
		return err
	}}
}

// voiceRow is one bridged call with a stereo recording and a split transcript.
func voiceRow(i int, sc demoCall, end time.Time, recDir string) (row, error) {
	at := end.Add(-time.Duration(1+i*5) * time.Hour)
	callID := fmt.Sprintf("demo-voice-%d", i)
	action, risk := score.ActionChallenge, 64
	reasons := []score.Reason{{Code: "caller_fanout", Weight: 25, Detail: "Called 48 different numbers in the last hour"}, {Code: "missing_identity", Weight: 15, Detail: "Identity header is missing"}}
	if sc.category == "none" {
		action, risk = score.ActionFlag, 41
		reasons = []score.Reason{{Code: "missing_identity", Weight: 15}}
	}
	secs := sc.turns[len(sc.turns)-1].end + 0.8
	rel := filepath.Join("demo", callID+".wav")
	if err := os.WriteFile(filepath.Join(recDir, rel), synthCall(sc.turns, secs, int64(i)), 0o640); err != nil {
		return row{}, err
	}
	turns := make([]map[string]any, 0, len(sc.turns))
	text := ""
	for j, t := range sc.turns {
		turns = append(turns, map[string]any{"speaker": t.speaker, "start": t.start, "end": t.end, "text": t.text})
		label := "Caller: "
		if t.speaker == "callee" {
			label = "Callee: "
		}
		if j > 0 {
			text += "\n"
		}
		text += label + t.text
	}
	tb, _ := json.Marshal(turns)
	ev := store.Event{ReceivedAt: at, Action: action, RiskScore: risk, SourceIP: "192.0.2.10", From: sc.from, To: sc.to,
		CallID: callID, UserAgent: "Asterisk PBX 18.20.0", Direction: "inbound", Switch: "sip/10.0.0.5", LatencyUS: 3100, Reasons: reasons}
	return row{ev: ev, after: func(ctx context.Context, db *store.SQLite, id int64) error {
		if _, err := db.AddVoiceSample(ctx, store.VoiceSample{EventID: id, CallID: callID, At: at.Add(time.Duration(secs) * time.Second), Seconds: secs, Channels: 2,
			CallerSpeech: 0.62, CalleeSpeech: 0.18, Transcript: text, Category: sc.category, Score: sc.score, Summary: sc.summary,
			Provider: "callerapi", From: sc.from, AudioPath: rel, Turns: tb}); err != nil {
			return err
		}
		if sc.category != "none" {
			_ = db.NoteVoiceScam(ctx, id, sc.category, sc.score, sc.summary)
		}
		mid, err := db.InsertMediaCall(ctx, store.MediaCall{EventID: id, CallID: callID, Carry: "challenge", From: sc.from, To: sc.to, StartedAt: at})
		if err != nil {
			return err
		}
		if err := db.UpdateMediaCall(ctx, store.MediaCall{ID: mid, EventID: id, LegBCallID: callID + "-b", RingMS: 1500, AnswerMS: 2600, ConnectMS: 2600,
			EndMS: 2600 + int(secs*1000), EndedBy: "caller", Status: 200, Codec: "PCMU/8000", Recording: rel, Seconds: secs, PacketsA: 600, PacketsB: 580}); err != nil {
			return err
		}
		_, err = db.SetOutcome(ctx, callID, store.Outcome{Answered: true, DurationS: int(secs), HangupCause: "bridge_caller"})
		return err
	}}, nil
}

// synthCall writes a stereo WAV: voice-like noise on the speaker's channel
// for each turn. The caller is left, the callee right.
func synthCall(turns []demoTurn, secs float64, seed int64) []byte {
	const rate = 8000
	n := int(secs * rate)
	rng := rand.New(rand.NewSource(seed))
	frames := make([]int16, n*2)
	for _, t := range turns {
		ch := 0
		if t.speaker == "callee" {
			ch = 1
		}
		for i := int(t.start * rate); i < int(t.end*rate) && i < n; i++ {
			env := 0.3 + 0.7*math.Abs(math.Sin(2*math.Pi*3.5*float64(i)/rate))
			frames[i*2+ch] = int16(rng.NormFloat64() * 2600 * env)
		}
	}
	data := make([]byte, len(frames)*2)
	for i, s := range frames {
		binary.LittleEndian.PutUint16(data[i*2:], uint16(s))
	}
	out := make([]byte, 44, 44+len(data))
	copy(out, "RIFF")
	binary.LittleEndian.PutUint32(out[4:], uint32(36+len(data)))
	copy(out[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(out[16:], 16)
	binary.LittleEndian.PutUint16(out[20:], 1)
	binary.LittleEndian.PutUint16(out[22:], 2)
	binary.LittleEndian.PutUint32(out[24:], rate)
	binary.LittleEndian.PutUint32(out[28:], rate*4)
	binary.LittleEndian.PutUint16(out[32:], 4)
	binary.LittleEndian.PutUint16(out[34:], 16)
	copy(out[36:], "data")
	binary.LittleEndian.PutUint32(out[40:], uint32(len(data)))
	return append(out, data...)
}
