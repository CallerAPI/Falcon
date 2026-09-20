// Package voice turns the first seconds of a suspicious call into evidence.
// Everything that can be decided without a model is decided here, on the
// host, for free: is this the same recording again, is one side talking
// into silence. Only then, and only within a budget, does a clip go to a
// transcription and classification provider the operator chose.
package voice

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Clip is decoded audio. Channels are kept apart when the switch recorded
// the legs separately: channel 0 is the caller, channel 1 the callee.
type Clip struct {
	Rate     int
	Channels [][]int16
}

// Seconds is the clip length.
func (c Clip) Seconds() float64 {
	if c.Rate == 0 || len(c.Channels) == 0 {
		return 0
	}
	return float64(len(c.Channels[0])) / float64(c.Rate)
}

// DecodeWAV reads 8 or 16 bit PCM WAV with one or two channels. Anything
// else is refused; the adapters record what this accepts.
func DecodeWAV(b []byte) (Clip, error) {
	if len(b) < 12 || string(b[0:4]) != "RIFF" || string(b[8:12]) != "WAVE" {
		return Clip{}, errors.New("not a RIFF/WAVE file")
	}
	var format, channels, bits, rate int
	var data []byte
	off := 12
	for off+8 <= len(b) {
		id := string(b[off : off+4])
		size := int(binary.LittleEndian.Uint32(b[off+4 : off+8]))
		off += 8
		if size < 0 || off+size > len(b) {
			size = len(b) - off
		}
		chunk := b[off : off+size]
		switch id {
		case "fmt ":
			if len(chunk) < 16 {
				return Clip{}, errors.New("short fmt chunk")
			}
			format = int(binary.LittleEndian.Uint16(chunk[0:2]))
			channels = int(binary.LittleEndian.Uint16(chunk[2:4]))
			rate = int(binary.LittleEndian.Uint32(chunk[4:8]))
			bits = int(binary.LittleEndian.Uint16(chunk[14:16]))
		case "data":
			data = chunk
		}
		off += size + size%2
	}
	if format != 1 && format != 0xFFFE {
		return Clip{}, fmt.Errorf("unsupported WAV format %d; record PCM", format)
	}
	if channels < 1 || channels > 2 || rate < 8000 || rate > 48000 {
		return Clip{}, fmt.Errorf("unsupported channels=%d rate=%d", channels, rate)
	}
	if bits != 16 && bits != 8 {
		return Clip{}, fmt.Errorf("unsupported %d bit samples", bits)
	}
	if len(data) == 0 {
		return Clip{}, errors.New("no audio data")
	}
	c := Clip{Rate: rate, Channels: make([][]int16, channels)}
	bytesPer := bits / 8
	frames := len(data) / (bytesPer * channels)
	for ch := range c.Channels {
		c.Channels[ch] = make([]int16, frames)
	}
	for i := 0; i < frames; i++ {
		for ch := 0; ch < channels; ch++ {
			p := (i*channels + ch) * bytesPer
			if bits == 16 {
				c.Channels[ch][i] = int16(binary.LittleEndian.Uint16(data[p : p+2]))
			} else {
				c.Channels[ch][i] = int16((int(data[p]) - 128) << 8)
			}
		}
	}
	return c, nil
}

// Features are what the host can tell without a model.
type Features struct {
	Seconds  float64 `json:"seconds"`
	Channels int     `json:"channels"`
	// CallerSpeech and CalleeSpeech are the share of 20 ms frames with
	// speech energy on each leg. With one channel both carry the mix.
	CallerSpeech float64 `json:"caller_speech"`
	CalleeSpeech float64 `json:"callee_speech"`
	// Monologue is true when one side talks and the other stays silent
	// for the whole clip: a recording played at a person.
	Monologue bool `json:"monologue"`
	// PHash is a 64 bit perceptual hash of the caller leg's energy
	// envelope. The same recording gives the same hash on every call.
	PHash string `json:"phash"`
}

const frameMs = 20

// Analyse computes features for a clip.
func Analyse(c Clip) Features {
	f := Features{Seconds: c.Seconds(), Channels: len(c.Channels)}
	if f.Seconds == 0 {
		return f
	}
	caller := energies(c.Channels[0], c.Rate)
	f.CallerSpeech = speechRatio(caller)
	if len(c.Channels) > 1 {
		callee := energies(c.Channels[1], c.Rate)
		f.CalleeSpeech = speechRatio(callee)
		f.Monologue = f.Seconds >= 8 && f.CallerSpeech >= 0.55 && f.CalleeSpeech <= 0.08
	} else {
		f.CalleeSpeech = f.CallerSpeech
	}
	f.PHash = phash(caller)
	return f
}

// energies is the RMS of each frame.
func energies(samples []int16, rate int) []float64 {
	n := rate * frameMs / 1000
	if n <= 0 {
		return nil
	}
	var out []float64
	for i := 0; i+n <= len(samples); i += n {
		var sum float64
		for _, s := range samples[i : i+n] {
			v := float64(s)
			sum += v * v
		}
		out = append(out, math.Sqrt(sum/float64(n)))
	}
	return out
}

// speechRatio is the share of frames above a floor set from the quietest
// frames, so a noisy line and a clean one are judged the same way.
func speechRatio(e []float64) float64 {
	if len(e) == 0 {
		return 0
	}
	sorted := append([]float64(nil), e...)
	sort.Float64s(sorted)
	floor := sorted[len(sorted)/10]
	threshold := math.Max(floor*3, 200)
	speech := 0
	for _, v := range e {
		if v > threshold {
			speech++
		}
	}
	return float64(speech) / float64(len(e))
}

// phash folds the first ten seconds of energy into 64 bins and sets a bit
// for each bin above the median. Two plays of the same recording differ
// in a few bits; two different calls differ in about half.
func phash(e []float64) string {
	limit := 10 * 1000 / frameMs
	if len(e) > limit {
		e = e[:limit]
	}
	if len(e) < 16 {
		return ""
	}
	bins := make([]float64, 64)
	for i := range bins {
		lo := i * len(e) / 64
		hi := (i + 1) * len(e) / 64
		if hi <= lo {
			hi = lo + 1
		}
		var sum float64
		for _, v := range e[lo:hi] {
			sum += v
		}
		bins[i] = sum / float64(hi-lo)
	}
	// Threshold on the mean, not the median: a two-level signal (tone,
	// silence, tone) would put every bin at or under the median and hash
	// to zero, and every such clip would then match every other.
	var mean float64
	for _, v := range bins {
		mean += v
	}
	mean /= float64(len(bins))
	var h uint64
	ones := 0
	for i, v := range bins {
		if v > mean {
			h |= 1 << uint(i)
			ones++
		}
	}
	if ones == 0 || ones == 64 {
		// Flat clip: silence or a constant tone. No shape to match on.
		return ""
	}
	return fmt.Sprintf("%016x", h)
}

// Hamming is the bit distance between two hashes. 64 means unrelated.
func Hamming(a, b string) int {
	x, err1 := strconv.ParseUint(strings.TrimSpace(a), 16, 64)
	y, err2 := strconv.ParseUint(strings.TrimSpace(b), 16, 64)
	if err1 != nil || err2 != nil {
		return 64
	}
	v := x ^ y
	n := 0
	for v != 0 {
		v &= v - 1
		n++
	}
	return n
}

// RepeatThreshold is the distance at or below which two clips are the
// same recording.
const RepeatThreshold = 8

// Repeats counts hashes within RepeatThreshold of h.
func Repeats(h string, recent []string) int {
	if h == "" {
		return 0
	}
	n := 0
	for _, r := range recent {
		if Hamming(h, r) <= RepeatThreshold {
			n++
		}
	}
	return n
}
