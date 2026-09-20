package voice

import (
	"encoding/binary"
	"math"
	"math/rand"
	"testing"
)

func wav(rate int, chans [][]int16) []byte {
	n := len(chans[0])
	data := make([]byte, 0, n*2*len(chans))
	for i := 0; i < n; i++ {
		for _, ch := range chans {
			data = binary.LittleEndian.AppendUint16(data, uint16(ch[i]))
		}
	}
	out := make([]byte, 44+len(data))
	copy(out, "RIFF")
	binary.LittleEndian.PutUint32(out[4:], uint32(36+len(data)))
	copy(out[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(out[16:], 16)
	binary.LittleEndian.PutUint16(out[20:], 1)
	binary.LittleEndian.PutUint16(out[22:], uint16(len(chans)))
	binary.LittleEndian.PutUint32(out[24:], uint32(rate))
	binary.LittleEndian.PutUint32(out[28:], uint32(rate*2*len(chans)))
	binary.LittleEndian.PutUint16(out[32:], uint16(2*len(chans)))
	binary.LittleEndian.PutUint16(out[34:], 16)
	copy(out[36:], "data")
	binary.LittleEndian.PutUint32(out[40:], uint32(len(data)))
	copy(out[44:], data)
	return out
}

// speech is a bursty tone pattern seeded so the same "recording" can be
// replayed; silence is low noise.
func speech(rate, seconds int, seed int64, on bool) []int16 {
	r := rand.New(rand.NewSource(seed))
	out := make([]int16, rate*seconds)
	for i := range out {
		t := float64(i) / float64(rate)
		burst := math.Sin(t*0.9+float64(seed)) > -0.2
		if on && burst {
			out[i] = int16(6000*math.Sin(2*math.Pi*220*t) + float64(r.Intn(400)-200))
		} else {
			out[i] = int16(r.Intn(60) - 30)
		}
	}
	return out
}

func TestMonologueAndRepeatDetection(t *testing.T) {
	rate := 8000
	robocall := wav(rate, [][]int16{speech(rate, 12, 7, true), speech(rate, 12, 8, false)})
	c, err := DecodeWAV(robocall)
	if err != nil {
		t.Fatal(err)
	}
	f := Analyse(c)
	if !f.Monologue || f.CallerSpeech < 0.5 || f.CalleeSpeech > 0.1 || f.PHash == "" {
		t.Fatalf("robocall features: %+v", f)
	}

	// Same recording again, with different line noise: near-identical hash.
	again := wav(rate, [][]int16{speech(rate, 12, 7, true), speech(rate, 12, 9, false)})
	c2, _ := DecodeWAV(again)
	f2 := Analyse(c2)
	if d := Hamming(f.PHash, f2.PHash); d > RepeatThreshold {
		t.Fatalf("replayed recording distance %d", d)
	}
	if Repeats(f.PHash, []string{f2.PHash, "0000000000000000"}) != 1 {
		t.Fatal("repeat count")
	}

	// A different recording: far apart.
	other := wav(rate, [][]int16{speech(rate, 12, 31, true), speech(rate, 12, 8, false)})
	c3, _ := DecodeWAV(other)
	if d := Hamming(f.PHash, Analyse(c3).PHash); d <= RepeatThreshold {
		t.Fatalf("different recording distance %d", d)
	}

	// A conversation: both sides talk, no monologue.
	conv := wav(rate, [][]int16{speech(rate, 12, 7, true), speech(rate, 12, 11, true)})
	c4, _ := DecodeWAV(conv)
	if f4 := Analyse(c4); f4.Monologue {
		t.Fatalf("conversation flagged as monologue: %+v", f4)
	}
}

func TestDecodeWAVRefusesJunk(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("RIFF....WAVE"), []byte("not audio at all")} {
		if _, err := DecodeWAV(b); err == nil {
			t.Fatal("accepted junk")
		}
	}
}

func TestCategoriesAndScamFilter(t *testing.T) {
	if !IsScamCategory("Tax Collection") || IsScamCategory("Store") || IsScamCategory("none") || IsScamCategory("Made Up") {
		t.Fatal("scam category filter")
	}
	if canonical("tax collection") != "Tax Collection" || canonical("") != "none" {
		t.Fatal("canonical")
	}
}
