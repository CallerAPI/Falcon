package voice

import (
	"encoding/binary"
	"testing"
)

func wavMono(rate, frames int) []byte {
	data := make([]byte, frames*2)
	for i := 0; i < frames; i++ {
		binary.LittleEndian.PutUint16(data[i*2:], uint16(i%1000))
	}
	out := make([]byte, 44+len(data))
	copy(out, "RIFF")
	binary.LittleEndian.PutUint32(out[4:], uint32(36+len(data)))
	copy(out[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(out[16:], 16)
	binary.LittleEndian.PutUint16(out[20:], 1)
	binary.LittleEndian.PutUint16(out[22:], 1)
	binary.LittleEndian.PutUint32(out[24:], uint32(rate))
	binary.LittleEndian.PutUint32(out[28:], uint32(rate*2))
	binary.LittleEndian.PutUint16(out[32:], 2)
	binary.LittleEndian.PutUint16(out[34:], 16)
	copy(out[36:], "data")
	binary.LittleEndian.PutUint32(out[40:], uint32(len(data)))
	copy(out[44:], data)
	return out
}

func TestTrimWAVKeepsTheOpening(t *testing.T) {
	in := wavMono(8000, 8000*40)
	out, err := TrimWAV(in, ScanSeconds)
	if err != nil {
		t.Fatal(err)
	}
	c, err := DecodeWAV(out)
	if err != nil {
		t.Fatal(err)
	}
	if c.Seconds() < 24.9 || c.Seconds() > 25.1 {
		t.Fatalf("seconds = %v", c.Seconds())
	}
	short := wavMono(8000, 8000*10)
	same, err := TrimWAV(short, ScanSeconds)
	if err != nil {
		t.Fatal(err)
	}
	if len(same) != len(short) {
		t.Fatalf("short clip changed length %d -> %d", len(short), len(same))
	}
}

func TestSplitWAVCoversTheWholeCall(t *testing.T) {
	in := wavMono(8000, 8000*70)
	parts, err := SplitWAV(in, ScanSeconds)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 3 {
		t.Fatalf("parts = %d", len(parts))
	}
	var frames int
	for i, p := range parts {
		c, err := DecodeWAV(p)
		if err != nil {
			t.Fatal(err)
		}
		if i < 2 && (c.Seconds() < 24.9 || c.Seconds() > 25.1) {
			t.Fatalf("part %d seconds = %v", i, c.Seconds())
		}
		frames += len(c.Channels[0])
	}
	if frames != 8000*70 {
		t.Fatalf("frames = %d", frames)
	}
}
