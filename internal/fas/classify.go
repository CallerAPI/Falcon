// Package fas hears false answer supervision on a bridged call: the far
// end sends 200 OK while the line still rings, plays busy, plays an
// intercept, or stays silent. It classifies callee audio in 40 ms frames
// and judges the call from what follows the answer.
package fas

import "math"

// FrameMS is the length of one analysed frame. 40 ms at 8 kHz resolves
// tones 25 Hz apart, enough to tell call progress tones from speech.
const (
	FrameMS      = 40
	sampleRate   = 8000
	frameSamples = sampleRate * FrameMS / 1000
)

// Class is what one frame holds.
type Class uint8

const (
	Silence Class = iota
	Speech
	Progress
	SIT1
	SIT2
	SIT3
)

func (c Class) String() string {
	switch c {
	case Speech:
		return "speech"
	case Progress:
		return "tone"
	case SIT1, SIT2, SIT3:
		return "sit"
	default:
		return "silence"
	}
}

type goertzel struct {
	coeff float64
}

// newGoertzel tunes a filter to the exact frequency, not the nearest bin.
// The power formula holds for any frequency.
func newGoertzel(freq float64) goertzel {
	return goertzel{coeff: 2 * math.Cos(2*math.Pi*freq/sampleRate)}
}

// share is the fraction of the frame's energy at this frequency. A pure
// tone at the frequency gives about 1.
func (g goertzel) share(frame []int16, energy float64) float64 {
	var s1, s2 float64
	for _, x := range frame {
		s0 := float64(x) + g.coeff*s1 - s2
		s2, s1 = s1, s0
	}
	power := s1*s1 + s2*s2 - g.coeff*s1*s2
	if energy <= 0 {
		return 0
	}
	return 2 * power / float64(len(frame)) / energy
}

// progressSets are the call progress tones of the world's networks:
// North American ringback, busy, and dial tone, the 425 Hz single tone of
// most of Europe, Latin America, and Asia, the UK 400 and 450 Hz pair,
// and the plain 400, 440, and 450 Hz singles some networks use.
var progressSets = [][]float64{
	{440, 480}, {480, 620}, {350, 440}, {400, 450}, {425}, {400}, {440}, {450},
}

// sitTones are the three Special Information Tone segments that open an
// intercept recording, with their low and high variants.
var sitTones = [3][]float64{{913.8, 985.2}, {1370.6, 1428.5}, {1776.7}}

// Frame is the label of one frame. Tone is the progress set that matched,
// so a burst can be checked for one steady tone.
type Frame struct {
	Class Class
	Tone  int
	Power float64
}

// Classifier labels frames. It keeps a noise floor from the quiet,
// non-tonal frames so a noisy line and a clean one are judged alike.
type Classifier struct {
	progress [][]goertzel
	sit      [3][]goertzel
	floor    float64
}

// NewClassifier builds the filter bank once per call. The floor starts at
// a quiet line, so a voice that starts before any pause still counts.
func NewClassifier() *Classifier {
	c := &Classifier{floor: dbfsToPower(-55)}
	for _, set := range progressSets {
		var gs []goertzel
		for _, f := range set {
			gs = append(gs, newGoertzel(f))
		}
		c.progress = append(c.progress, gs)
	}
	for i, set := range sitTones {
		for _, f := range set {
			c.sit[i] = append(c.sit[i], newGoertzel(f))
		}
	}
	return c
}

// Levels in mean square on the int16 scale. -48 dBFS is the quietest frame
// that can carry a tone or a voice on a telephone line.
var (
	silenceLevel = dbfsToPower(-48)
	speechLevel  = dbfsToPower(-42)
)

func dbfsToPower(db float64) float64 {
	a := 32768 * math.Pow(10, db/20)
	return a * a
}

// Classify labels one frame.
func (c *Classifier) Classify(frame []int16) Frame {
	var sum float64
	for _, x := range frame {
		v := float64(x)
		sum += v * v
	}
	power := sum / float64(len(frame))
	if power < silenceLevel {
		c.learn(power)
		return Frame{Class: Silence, Power: power}
	}
	for i := range c.sit {
		for _, g := range c.sit[i] {
			if g.share(frame, sum) >= 0.7 {
				return Frame{Class: SIT1 + Class(i), Power: power}
			}
		}
	}
	best, which := 0.0, -1
	for i, set := range c.progress {
		total := 0.0
		for _, g := range set {
			total += g.share(frame, sum)
		}
		if total > best {
			best, which = total, i
		}
	}
	if best >= 0.75 {
		return Frame{Class: Progress, Tone: which, Power: power}
	}
	c.learn(power)
	if power >= speechLevel && power >= c.floor*8 {
		return Frame{Class: Speech, Power: power}
	}
	return Frame{Class: Silence, Power: power}
}

// learn follows the noise floor: down at once, up slowly. The gaps
// between words pull it back down, so speech stays well above it.
func (c *Classifier) learn(power float64) {
	if power < c.floor {
		c.floor = math.Max(power, 1)
		return
	}
	c.floor = math.Min(c.floor*1.01, power)
}
