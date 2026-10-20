package fas

import (
	"sync"
	"time"
)

// Kind is what the guard heard after the far end answered.
type Kind string

const (
	Clean    Kind = ""
	Ringback Kind = "ringback"
	Busy     Kind = "busy"
	SIT      Kind = "sit"
	DeadAir  Kind = "dead_air"
)

// Signal is a change the guard acts on while it holds an answer.
type Signal uint8

const (
	None Signal = iota
	// SpeechStarted means a person or a recorded voice is talking.
	SpeechStarted
	// ToneHeard means call progress tone kept playing after the answer.
	ToneHeard
	// SITHeard means an intercept opened after the answer.
	SITHeard
)

// Timing rules, in milliseconds unless named in frames.
const (
	toneMS          = 600  // progress tone after an answer that makes it false
	longBurstMS     = 600  // a ringback burst is at least this long
	shortBurstMinMS = 160  // shorter than this is noise
	shortGapMaxMS   = 800  // busy and reorder bursts repeat at least this fast
	speechFrames    = 6    // 240 ms of speech
	sitFrames       = 4    // 160 ms per SIT segment
	sitWindowFrames = 50   // the three segments within 2 s
	deadAirMinMS    = 4000 // answered silence shorter than this is not judged
	minBurstFrames  = 3
)

// busyTones are progress sets that only ever mean busy or reorder:
// North American 480 plus 620 Hz, and the 400 Hz single of the UK.
// ringTones only ever mean ringback: 440 plus 480 Hz and the UK double
// ring at 400 plus 450 Hz, which comes in short pairs.
var (
	busyTones = map[int]bool{1: true, 5: true}
	ringTones = map[int]bool{0: true, 3: true}
)

// Burst is one stretch of progress tone, in ms after the INVITE.
type Burst struct {
	Start int `json:"start_ms"`
	End   int `json:"end_ms"`
}

// Detail is the evidence kept with a verdict. Times are ms after the INVITE.
type Detail struct {
	AnswerMS      int     `json:"answer_ms"`
	FirstSpeechMS int     `json:"first_speech_ms,omitempty"`
	ToneMS        int     `json:"tone_after_answer_ms,omitempty"`
	ToneBefore    bool    `json:"tone_before_answer,omitempty"`
	SpeechMS      int     `json:"callee_speech_ms"`
	AudioFrames   int     `json:"callee_frames_after_answer"`
	Bursts        []Burst `json:"bursts,omitempty"`
	SIT           bool    `json:"sit,omitempty"`
}

// Verdict is the judgment on a call once it ends.
type Verdict struct {
	Kind Kind
	// FalseMS is answered time that was not a conversation: the billed
	// seconds a false answer added.
	FalseMS int
	Detail  Detail
}

type burst struct {
	start, frames, tone int
	counted             int
}

// Detector consumes the callee's decoded audio for one call. Feed runs on
// the relay goroutine. Answer, Verdict, and Signals may run elsewhere.
type Detector struct {
	mu       sync.Mutex
	cls      *Classifier
	start    time.Time
	buf      []int16
	answered bool
	answerMS int
	signals  chan Signal

	cur        *burst
	lastShort  *Burst
	toneMS     int
	busyVotes  int
	ringVotes  int
	toneBefore bool
	bursts     []Burst

	speechRun, speechGap int
	afterAnswerFrames    int
	speechMS             int
	firstSpeechMS        int
	speechAfterToneMS    int

	sitStage, sitRun, sitStartFrame int
	sit                             bool
	frameNo                         int

	sentTone, sentSIT, sentSpeech bool
}

// NewDetector starts the clock at the INVITE.
func NewDetector(start time.Time) *Detector {
	return &Detector{cls: NewClassifier(), start: start, signals: make(chan Signal, 8), firstSpeechMS: -1, speechAfterToneMS: -1}
}

// Signals delivers SpeechStarted, ToneHeard, and SITHeard once each.
func (d *Detector) Signals() <-chan Signal { return d.signals }

// Answer marks the moment the far end sent 200 OK.
func (d *Detector) Answer(at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.answered {
		return
	}
	d.answered = true
	d.answerMS = d.ms(at)
	if d.cur != nil {
		// A burst that straddles the answer counts from the answer on.
		d.toneBefore = true
		d.cur.start, d.cur.frames, d.cur.counted = d.answerMS, 0, 0
	}
	d.lastShort = nil
	d.speechRun = 0
}

func (d *Detector) ms(at time.Time) int { return int(at.Sub(d.start) / time.Millisecond) }

// Feed adds callee samples that arrived at the given time.
func (d *Detector) Feed(pcm []int16, at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.ms(at)
	d.buf = append(d.buf, pcm...)
	for len(d.buf) >= frameSamples {
		f := d.cls.Classify(d.buf[:frameSamples])
		d.buf = d.buf[frameSamples:]
		d.frame(f, now)
	}
}

func (d *Detector) frame(f Frame, now int) {
	d.frameNo++
	d.toneFrame(f, now)
	if !d.answered {
		return
	}
	d.afterAnswerFrames++
	d.sitFrame(f.Class)
	if f.Class == Speech {
		d.speechRun++
		d.speechGap = 0
		d.speechMS += FrameMS
		if d.speechRun >= speechFrames {
			start := now - (d.speechRun-1)*FrameMS
			if d.firstSpeechMS < 0 {
				d.firstSpeechMS = start
			}
			if d.toneMS > 0 && d.speechAfterToneMS < 0 {
				d.speechAfterToneMS = start
			}
			if !d.sentSpeech {
				d.sentSpeech = true
				d.emit(SpeechStarted)
			}
		}
		return
	}
	// One frame of dropout inside a word does not end the run.
	d.speechGap++
	if d.speechGap > 1 {
		d.speechRun = 0
	}
}

// toneFrame tracks bursts of one steady progress tone. A long burst is
// ringback. Short bursts count only when they repeat fast, the way busy
// and reorder tones do, so a note in hold music does not.
func (d *Detector) toneFrame(f Frame, now int) {
	tone := f.Class == Progress
	if tone && d.cur != nil && d.cur.tone != f.Tone {
		d.closeBurst(now)
	}
	if tone {
		if d.cur == nil {
			d.cur = &burst{start: now - FrameMS, tone: f.Tone}
			if d.answered && d.cur.start < d.answerMS {
				d.cur.start = d.answerMS
			}
		}
		d.cur.frames++
		if !d.answered {
			if d.cur.frames >= minBurstFrames {
				d.toneBefore = true
			}
			return
		}
		if length := now - d.cur.start; length >= longBurstMS {
			d.count(length - d.cur.counted)
			d.cur.counted = length
		}
		return
	}
	if d.cur != nil {
		d.closeBurst(now)
	}
}

func (d *Detector) closeBurst(now int) {
	b := d.cur
	d.cur = nil
	if b.frames < minBurstFrames || !d.answered {
		return
	}
	end := now - FrameMS
	length := end - b.start
	switch {
	case length >= longBurstMS:
		d.count(length - b.counted)
		d.bursts = append(d.bursts, Burst{Start: b.start, End: end})
		if busyTones[b.tone] {
			d.busyVotes++
		} else {
			d.ringVotes++
		}
	case length >= shortBurstMinMS:
		this := Burst{Start: b.start, End: end}
		if prev := d.lastShort; prev != nil && this.Start-prev.End <= shortGapMaxMS {
			if len(d.bursts) == 0 || d.bursts[len(d.bursts)-1] != *prev {
				d.count(prev.End - prev.Start)
				d.bursts = append(d.bursts, *prev)
			}
			d.count(length)
			d.bursts = append(d.bursts, this)
			if ringTones[b.tone] {
				d.ringVotes++
			} else {
				d.busyVotes++
			}
		}
		d.lastShort = &this
	}
}

func (d *Detector) count(ms int) {
	if ms <= 0 {
		return
	}
	d.toneMS += ms
	if d.toneMS >= toneMS && !d.sentTone {
		d.sentTone = true
		d.emit(ToneHeard)
	}
}

func (d *Detector) sitFrame(c Class) {
	want := SIT1 + Class(d.sitStage)
	switch {
	case d.sitStage < 3 && c == want:
		if d.sitStage == 0 && d.sitRun == 0 {
			d.sitStartFrame = d.frameNo
		}
		d.sitRun++
		if d.sitRun >= sitFrames {
			d.sitStage++
			d.sitRun = 0
			if d.sitStage == 3 && d.frameNo-d.sitStartFrame <= sitWindowFrames {
				d.sit = true
				if !d.sentSIT {
					d.sentSIT = true
					d.emit(SITHeard)
				}
			}
		}
	case d.sitStage > 0 && c == want-1:
		// Still in the previous segment.
	case d.sitStage > 0 && d.frameNo-d.sitStartFrame > sitWindowFrames:
		d.sitStage, d.sitRun = 0, 0
	case c == SIT1:
		d.sitStage, d.sitRun, d.sitStartFrame = 0, 1, d.frameNo
	}
}

func (d *Detector) emit(s Signal) {
	select {
	case d.signals <- s:
	default:
	}
}

// Verdict judges the call. end is when it ended.
func (d *Detector) Verdict(end time.Time) Verdict {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.answered {
		return Verdict{}
	}
	endMS := d.ms(end)
	if d.cur != nil {
		d.closeBurst(endMS + FrameMS)
	}
	detail := Detail{
		AnswerMS: d.answerMS, ToneMS: d.toneMS, ToneBefore: d.toneBefore, SpeechMS: d.speechMS,
		AudioFrames: d.afterAnswerFrames, Bursts: append([]Burst(nil), d.bursts...), SIT: d.sit,
	}
	if d.firstSpeechMS >= 0 {
		detail.FirstSpeechMS = d.firstSpeechMS
	}
	answered := endMS - d.answerMS
	if answered < 0 {
		answered = 0
	}
	v := Verdict{Detail: detail}
	switch {
	case d.sit:
		v.Kind, v.FalseMS = SIT, answered
	case d.toneMS >= toneMS:
		v.Kind = Ringback
		if d.busyVotes > d.ringVotes {
			v.Kind = Busy
		}
		v.FalseMS = answered
		if d.speechAfterToneMS > 0 {
			v.FalseMS = d.speechAfterToneMS - d.answerMS
		}
	case d.speechMS == 0 && answered >= deadAirMinMS:
		v.Kind, v.FalseMS = DeadAir, answered
	}
	if v.FalseMS < 0 {
		v.FalseMS = 0
	}
	return v
}
