package media

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SampleRate is the rate of every recording. G.711 is 8 kHz.
const SampleRate = 8000

// ErrEmpty means no audio was decoded on either side.
var ErrEmpty = errors.New("media: nothing recorded")

// Recorder writes the two sides of a call as one stereo WAV: the caller
// on the left channel, the callee on the right. Each side is placed on
// one timeline by arrival time and RTP timestamp, so gaps become silence
// and the two voices stay in step.
type Recorder struct {
	dir   string
	rel   string
	start time.Time
	max   int64
	ch    [2]*track
	done  atomic.Bool
}

type track struct {
	mu      sync.Mutex
	path    string
	f       *os.File
	w       *bufio.Writer
	written int64
	ssrc    uint32
	baseTS  uint32
	baseAt  int64
	based   bool
}

// NewRecorder starts a recording under dir. rel is the final path of the
// WAV relative to dir. start is time zero for both sides.
func NewRecorder(dir, rel string, start time.Time, maxSeconds int) (*Recorder, error) {
	if maxSeconds <= 0 {
		maxSeconds = 1800
	}
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return nil, err
	}
	r := &Recorder{dir: dir, rel: rel, start: start, max: int64(maxSeconds) * SampleRate}
	for i := range r.ch {
		path := full + ".ch" + string(rune('0'+i)) + ".raw"
		f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
		if err != nil {
			r.Abort()
			return nil, err
		}
		r.ch[i] = &track{path: path, f: f, w: bufio.NewWriterSize(f, 32<<10)}
	}
	return r, nil
}

// Rel is the path the finished WAV will have, relative to the folder.
func (r *Recorder) Rel() string { return r.rel }

var zeros = make([]byte, 4096)

// Audio places decoded samples on the timeline of their side.
func (r *Recorder) Audio(side Side, ssrc, ts uint32, pcm []int16, at time.Time) {
	if r.done.Load() || len(pcm) == 0 || side < SideA || side > SideB {
		return
	}
	t := r.ch[side]
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f == nil {
		return
	}
	arrival := int64(at.Sub(r.start)) * SampleRate / int64(time.Second)
	if arrival < 0 {
		arrival = 0
	}
	pos := arrival
	if t.based && ssrc == t.ssrc {
		pos = t.baseAt + int64(int32(ts-t.baseTS))
		if d := pos - arrival; d > 2*SampleRate || d < -2*SampleRate {
			t.based = false
			pos = arrival
		}
	}
	if !t.based || ssrc != t.ssrc {
		t.based, t.ssrc, t.baseTS, t.baseAt = true, ssrc, ts, arrival
		pos = arrival
	}
	if pos < t.written {
		skip := t.written - pos
		if skip >= int64(len(pcm)) {
			return
		}
		pcm = pcm[skip:]
		pos = t.written
	}
	if pos > r.max {
		return
	}
	for gap := pos - t.written; gap > 0; {
		n := gap * 2
		if n > int64(len(zeros)) {
			n = int64(len(zeros))
		}
		if _, err := t.w.Write(zeros[:n]); err != nil {
			return
		}
		gap -= n / 2
		t.written += n / 2
	}
	if room := r.max - t.written; int64(len(pcm)) > room {
		pcm = pcm[:room]
	}
	var b [2]byte
	for _, s := range pcm {
		binary.LittleEndian.PutUint16(b[:], uint16(s))
		if _, err := t.w.Write(b[:]); err != nil {
			return
		}
	}
	t.written += int64(len(pcm))
}

// Finish writes the stereo WAV and removes the per-side files. It returns
// the path relative to the folder and the length in seconds.
func (r *Recorder) Finish() (string, float64, error) {
	if !r.done.CompareAndSwap(false, true) {
		return "", 0, errors.New("media: recording already closed")
	}
	frames := int64(0)
	for _, t := range r.ch {
		t.mu.Lock()
		_ = t.w.Flush()
		_ = t.f.Close()
		t.f = nil
		if t.written > frames {
			frames = t.written
		}
		t.mu.Unlock()
	}
	defer r.removeTracks()
	if frames == 0 {
		return "", 0, ErrEmpty
	}
	full := filepath.Join(r.dir, r.rel)
	out, err := os.OpenFile(full, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return "", 0, err
	}
	w := bufio.NewWriterSize(out, 64<<10)
	if err := writeStereo(w, r.ch[0].path, r.ch[1].path, frames); err != nil {
		_ = out.Close()
		_ = os.Remove(full)
		return "", 0, err
	}
	if err := w.Flush(); err != nil {
		_ = out.Close()
		_ = os.Remove(full)
		return "", 0, err
	}
	if err := out.Close(); err != nil {
		return "", 0, err
	}
	return r.rel, float64(frames) / SampleRate, nil
}

// Abort drops the recording.
func (r *Recorder) Abort() {
	r.done.Store(true)
	for _, t := range r.ch {
		if t == nil {
			continue
		}
		t.mu.Lock()
		if t.f != nil {
			_ = t.f.Close()
			t.f = nil
		}
		t.mu.Unlock()
	}
	r.removeTracks()
}

func (r *Recorder) removeTracks() {
	for _, t := range r.ch {
		if t != nil {
			_ = os.Remove(t.path)
		}
	}
}

func writeStereo(w io.Writer, left, right string, frames int64) error {
	header := make([]byte, 44)
	data := uint32(frames * 4)
	copy(header, "RIFF")
	binary.LittleEndian.PutUint32(header[4:], 36+data)
	copy(header[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(header[16:], 16)
	binary.LittleEndian.PutUint16(header[20:], 1)
	binary.LittleEndian.PutUint16(header[22:], 2)
	binary.LittleEndian.PutUint32(header[24:], SampleRate)
	binary.LittleEndian.PutUint32(header[28:], SampleRate*4)
	binary.LittleEndian.PutUint16(header[32:], 4)
	binary.LittleEndian.PutUint16(header[34:], 16)
	copy(header[36:], "data")
	binary.LittleEndian.PutUint32(header[40:], data)
	if _, err := w.Write(header); err != nil {
		return err
	}
	l, err := os.Open(left)
	if err != nil {
		return err
	}
	defer l.Close()
	rt, err := os.Open(right)
	if err != nil {
		return err
	}
	defer rt.Close()
	lr, rr := bufio.NewReaderSize(l, 32<<10), bufio.NewReaderSize(rt, 32<<10)
	var ls, rs [2]byte
	out := make([]byte, 0, 4096)
	for i := int64(0); i < frames; i++ {
		ls, rs = [2]byte{}, [2]byte{}
		_, _ = io.ReadFull(lr, ls[:])
		_, _ = io.ReadFull(rr, rs[:])
		out = append(out, ls[0], ls[1], rs[0], rs[1])
		if len(out) >= 4096 {
			if _, err := w.Write(out); err != nil {
				return err
			}
			out = out[:0]
		}
	}
	if len(out) > 0 {
		if _, err := w.Write(out); err != nil {
			return err
		}
	}
	return nil
}

// RecordingName is a dated path for a call's recording. The Call-ID is
// cleaned so it cannot climb out of the folder.
func RecordingName(at time.Time, callID string) string {
	var b strings.Builder
	for _, c := range callID {
		if b.Len() >= 40 {
			break
		}
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		}
	}
	var tag [4]byte
	_, _ = rand.Read(tag[:])
	name := b.String()
	if name == "" {
		name = "call"
	}
	return filepath.Join(at.UTC().Format("2006"), at.UTC().Format("01"), at.UTC().Format("02"), name+"-"+hex.EncodeToString(tag[:])+".wav")
}
