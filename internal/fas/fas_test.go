package fas

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

type clip struct {
	samples []int16
}

func (c *clip) tone(ms int, freqs ...float64) *clip {
	n := ms * sampleRate / 1000
	start := len(c.samples)
	for i := 0; i < n; i++ {
		t := float64(start+i) / sampleRate
		v := 0.0
		for _, f := range freqs {
			v += math.Sin(2 * math.Pi * f * t)
		}
		c.samples = append(c.samples, int16(v/float64(len(freqs))*6000))
	}
	return c
}

func (c *clip) silence(ms int) *clip {
	c.samples = append(c.samples, make([]int16, ms*sampleRate/1000)...)
	return c
}

// speech is noise under a four syllables a second envelope. It has the
// energy and spread of a voice and no steady tone.
func (c *clip) speech(ms int, seed int64) *clip {
	rng := rand.New(rand.NewSource(seed))
	n := ms * sampleRate / 1000
	for i := 0; i < n; i++ {
		env := 0.35 + 0.65*math.Abs(math.Sin(2*math.Pi*4*float64(i)/sampleRate))
		c.samples = append(c.samples, int16(rng.NormFloat64()*4000*env))
	}
	return c
}

func (c *clip) ringbackUS(cycles int) *clip {
	for i := 0; i < cycles; i++ {
		c.tone(2000, 440, 480).silence(4000)
	}
	return c
}

// play feeds the clip in 20 ms packets as if they arrived in real time,
// answering at answerMS. It returns the signals in order.
func play(d *Detector, start time.Time, c *clip, answerMS int) []Signal {
	var got []Signal
	for off := 0; off+160 <= len(c.samples); off += 160 {
		at := start.Add(time.Duration(off/8) * time.Millisecond)
		if answerMS >= 0 && off/8 == answerMS {
			d.Answer(at)
		}
		d.Feed(c.samples[off:off+160], at)
		for {
			select {
			case s := <-d.Signals():
				got = append(got, s)
				continue
			default:
			}
			break
		}
	}
	return got
}

func end(start time.Time, c *clip) time.Time {
	return start.Add(time.Duration(len(c.samples)/8) * time.Millisecond)
}

func TestCleanAnswerIsClean(t *testing.T) {
	start := time.Now()
	c := (&clip{}).ringbackUS(1).speech(4000, 1)
	d := NewDetector(start)
	sigs := play(d, start, c, 6000)
	v := d.Verdict(end(start, c))
	if v.Kind != Clean || v.FalseMS != 0 {
		t.Fatalf("verdict %+v", v)
	}
	if len(sigs) != 1 || sigs[0] != SpeechStarted {
		t.Fatalf("signals %v", sigs)
	}
	if !v.Detail.ToneBefore || v.Detail.FirstSpeechMS < 6000 || v.Detail.FirstSpeechMS > 6300 {
		t.Fatalf("detail %+v", v.Detail)
	}
}

func TestRingbackAfterAnswerIsFAS(t *testing.T) {
	start := time.Now()
	// The far end answers 2 s into the first ring, keeps ringing for two
	// more cycles, then a person picks up at 14 s.
	c := (&clip{}).tone(2000, 440, 480).silence(4000).ringbackUS(1).tone(2000, 440, 480).speech(3000, 2)
	d := NewDetector(start)
	sigs := play(d, start, c, 1000)
	v := d.Verdict(end(start, c))
	if v.Kind != Ringback {
		t.Fatalf("kind %q detail %+v", v.Kind, v.Detail)
	}
	if v.FalseMS < 12500 || v.FalseMS > 13300 {
		t.Fatalf("false ms %d", v.FalseMS)
	}
	if len(sigs) < 2 || sigs[0] != ToneHeard || sigs[len(sigs)-1] != SpeechStarted {
		t.Fatalf("signals %v", sigs)
	}
}

func TestEuropeanRingbackUntilHangupIsAllFalse(t *testing.T) {
	start := time.Now()
	c := (&clip{}).tone(1000, 425).silence(4000).tone(1000, 425).silence(4000).tone(1000, 425)
	d := NewDetector(start)
	play(d, start, c, 500)
	v := d.Verdict(end(start, c))
	if v.Kind != Ringback || v.FalseMS != len(c.samples)/8-500 {
		t.Fatalf("verdict %+v", v)
	}
}

func TestUKDoubleRingAfterAnswerIsRingback(t *testing.T) {
	start := time.Now()
	c := &clip{}
	for i := 0; i < 3; i++ {
		c.tone(400, 400, 450).silence(200).tone(400, 400, 450).silence(2000)
	}
	d := NewDetector(start)
	play(d, start, c, 0)
	if v := d.Verdict(end(start, c)); v.Kind != Ringback {
		t.Fatalf("kind %q bursts %+v", v.Kind, v.Detail.Bursts)
	}
}

func TestBusyAfterAnswer(t *testing.T) {
	start := time.Now()
	c := &clip{}
	for i := 0; i < 6; i++ {
		c.tone(500, 480, 620).silence(500)
	}
	d := NewDetector(start)
	sigs := play(d, start, c, 0)
	v := d.Verdict(end(start, c))
	if v.Kind != Busy {
		t.Fatalf("kind %q bursts %+v", v.Kind, v.Detail.Bursts)
	}
	if len(sigs) == 0 || sigs[0] != ToneHeard {
		t.Fatalf("signals %v", sigs)
	}
}

func TestInterceptAfterAnswer(t *testing.T) {
	start := time.Now()
	c := (&clip{}).silence(200).tone(330, 913.8).tone(330, 1370.6).tone(330, 1776.7).speech(3000, 3)
	d := NewDetector(start)
	sigs := play(d, start, c, 0)
	v := d.Verdict(end(start, c))
	if v.Kind != SIT || !v.Detail.SIT {
		t.Fatalf("verdict %+v", v)
	}
	if len(sigs) == 0 || sigs[0] != SITHeard {
		t.Fatalf("signals %v", sigs)
	}
}

func TestDeadAirAfterAnswer(t *testing.T) {
	start := time.Now()
	c := (&clip{}).silence(6000)
	d := NewDetector(start)
	play(d, start, c, 0)
	if v := d.Verdict(end(start, c)); v.Kind != DeadAir || v.FalseMS != 6000 {
		t.Fatalf("verdict %+v", v)
	}
}

func TestShortSilentAnswerIsNotJudged(t *testing.T) {
	start := time.Now()
	c := (&clip{}).silence(2000)
	d := NewDetector(start)
	play(d, start, c, 0)
	if v := d.Verdict(end(start, c)); v.Kind != Clean {
		t.Fatalf("verdict %+v", v)
	}
}

func TestMusicIsNotRingback(t *testing.T) {
	start := time.Now()
	c := &clip{}
	notes := []float64{392, 440, 494, 523, 587, 659, 698, 784}
	for i := 0; i < 40; i++ {
		c.tone(200, notes[i%len(notes)])
	}
	d := NewDetector(start)
	play(d, start, c, 0)
	if v := d.Verdict(end(start, c)); v.Kind == Ringback || v.Kind == Busy {
		t.Fatalf("music judged as %q: %+v", v.Kind, v.Detail)
	}
}

func TestNoAnswerNoVerdict(t *testing.T) {
	start := time.Now()
	c := (&clip{}).ringbackUS(2)
	d := NewDetector(start)
	play(d, start, c, -1)
	if v := d.Verdict(end(start, c)); v.Kind != Clean || v.FalseMS != 0 {
		t.Fatalf("verdict %+v", v)
	}
}
