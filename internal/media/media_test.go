package media

import (
	"encoding/binary"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestULawRoundTripStaysClose(t *testing.T) {
	for _, s := range []int16{0, 100, -100, 1000, -1000, 8000, -8000, 30000, -30000} {
		got := DecodeULaw(nil, EncodeULaw(nil, []int16{s}))[0]
		if diff := math.Abs(float64(got) - float64(s)); diff > math.Max(64, math.Abs(float64(s))*0.07) {
			t.Fatalf("sample %d came back as %d", s, got)
		}
	}
}

func TestALawDecodesSilenceNearZero(t *testing.T) {
	if got := DecodeALaw(nil, []byte{0xD5})[0]; got > 16 || got < -16 {
		t.Fatalf("A-law 0xD5 is %d, want near zero", got)
	}
}

func TestRTPRoundTrip(t *testing.T) {
	in := Packet{Marker: true, PayloadType: 8, Sequence: 65535, Timestamp: 4294967200, SSRC: 7, Payload: []byte{1, 2, 3}}
	out, ok := ParseRTP(BuildRTP(in))
	if !ok || out.PayloadType != 8 || out.Sequence != 65535 || out.Timestamp != in.Timestamp || out.SSRC != 7 || !out.Marker || string(out.Payload) != string(in.Payload) {
		t.Fatalf("round trip: %+v", out)
	}
	if _, ok := ParseRTP([]byte{0x40, 0, 0}); ok {
		t.Fatal("short or wrong-version packet parsed")
	}
}

const offer = "v=0\r\no=switch 4711 1 IN IP4 198.51.100.7\r\ns=-\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\n" +
	"m=audio 30000 RTP/AVP 18 0 8 101\r\na=rtpmap:18 G729/8000\r\na=rtpmap:101 telephone-event/8000\r\n" +
	"a=fmtp:101 0-16\r\na=rtcp:30001\r\na=candidate:1 1 UDP 1 198.51.100.7 30000 typ host\r\na=sendrecv\r\n" +
	"m=video 30002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"

func TestSDPParseAndRewrite(t *testing.T) {
	s, err := ParseSDP([]byte(offer))
	if err != nil {
		t.Fatal(err)
	}
	if s.Addr != "198.51.100.7" || s.Port != 30000 || len(s.Payloads) != 4 || s.Codecs[0] != "PCMU/8000" || s.Codecs[101] != "telephone-event/8000" {
		t.Fatalf("parsed %+v", s)
	}
	if pt, name := s.Codec(); pt != 18 || name != "G729/8000" {
		t.Fatalf("codec %d %s", pt, name)
	}
	body := string(s.Rewrite("203.0.113.5", 20000, true))
	for _, want := range []string{"o=switch 4711 1 IN IP4 203.0.113.5", "c=IN IP4 203.0.113.5", "m=audio 20000 RTP/AVP 0 8 18 101", "m=video 0 RTP/AVP 96", "a=fmtp:101 0-16", "a=sendrecv"} {
		if !strings.Contains(body, want) {
			t.Fatalf("rewrite lacks %q:\n%s", want, body)
		}
	}
	for _, gone := range []string{"198.51.100.7", "a=rtcp:", "a=candidate"} {
		if strings.Contains(body, gone) {
			t.Fatalf("rewrite kept %q:\n%s", gone, body)
		}
	}
	again, err := ParseSDP([]byte(body))
	if err != nil || again.Port != 20000 || again.Addr != "203.0.113.5" {
		t.Fatalf("rewritten SDP does not parse back: %v %+v", err, again)
	}
}

func TestSDPWithoutAudioIsRefused(t *testing.T) {
	if _, err := ParseSDP([]byte("v=0\r\nm=video 4000 RTP/AVP 96\r\n")); err != ErrNoAudio {
		t.Fatalf("err %v", err)
	}
}

type captureTap struct {
	mu      sync.Mutex
	samples map[Side]int
}

func (c *captureTap) Audio(side Side, _, _ uint32, pcm []int16, _ time.Time) {
	c.mu.Lock()
	c.samples[side] += len(pcm)
	c.mu.Unlock()
}

func TestRelayForwardsBothWaysAndDecodes(t *testing.T) {
	alloc := NewAllocator("127.0.0.1", 41000, 41100)
	a, err := alloc.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := alloc.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	tap := &captureTap{samples: map[Side]int{}}
	r := NewRelay(a, b, tap)
	r.SetCodecs(SideA, map[uint8]string{0: "PCMU/8000"})
	r.SetCodecs(SideB, map[uint8]string{0: "PCMU/8000"})
	callerEnd, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	calleeEnd, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer callerEnd.Close()
	defer calleeEnd.Close()
	_ = r.SetRemote(SideA, "127.0.0.1", callerEnd.LocalAddr().(*net.UDPAddr).Port)
	_ = r.SetRemote(SideB, "127.0.0.1", calleeEnd.LocalAddr().(*net.UDPAddr).Port)
	r.Start()
	defer func() { r.Close(); alloc.Release(a); alloc.Release(b) }()

	pkt := BuildRTP(Packet{PayloadType: 0, Sequence: 1, Timestamp: 160, SSRC: 1, Payload: EncodeULaw(nil, make([]int16, 160))})
	_, _ = callerEnd.WriteToUDP(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.Port(SideA)})
	_, _ = calleeEnd.WriteToUDP(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.Port(SideB)})

	buf := make([]byte, 1500)
	_ = calleeEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _, err := calleeEnd.ReadFromUDP(buf); err != nil || n != len(pkt) {
		t.Fatalf("callee did not get the caller packet: %v", err)
	}
	_ = callerEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _, err := callerEnd.ReadFromUDP(buf); err != nil || n != len(pkt) {
		t.Fatalf("caller did not get the callee packet: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		tap.mu.Lock()
		done := tap.samples[SideA] == 160 && tap.samples[SideB] == 160
		tap.mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r.Packets(SideA) != 1 || r.Packets(SideB) != 1 || r.LastPacket().IsZero() {
		t.Fatalf("counters a=%d b=%d", r.Packets(SideA), r.Packets(SideB))
	}
	tap.mu.Lock()
	defer tap.mu.Unlock()
	if tap.samples[SideA] != 160 || tap.samples[SideB] != 160 {
		t.Fatalf("tap saw %v", tap.samples)
	}
}

func TestRecorderKeepsBothSidesInStep(t *testing.T) {
	dir := t.TempDir()
	start := time.Now()
	rel := RecordingName(start, "abc/../../etc@host")
	if strings.Contains(rel, "..") || strings.Contains(rel, "@") {
		t.Fatalf("unsafe name %q", rel)
	}
	rec, err := NewRecorder(dir, rel, start, 60)
	if err != nil {
		t.Fatal(err)
	}
	tone := make([]int16, 160)
	for i := range tone {
		tone[i] = 1000
	}
	// Caller talks at 0 s and 1 s. The 1 s packet arrives with a gap.
	rec.Audio(SideA, 1, 0, tone, start)
	rec.Audio(SideA, 1, 8000, tone, start.Add(time.Second))
	// Callee starts at 0.5 s with a different clock base.
	rec.Audio(SideB, 2, 99999, tone, start.Add(500*time.Millisecond))
	// A late duplicate is ignored.
	rec.Audio(SideA, 1, 0, tone, start.Add(1100*time.Millisecond))
	got, secs, err := rec.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if got != rel || math.Abs(secs-(1.0+160.0/8000)) > 0.001 {
		t.Fatalf("finish %q %.3f", got, secs)
	}
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	if string(b[0:4]) != "RIFF" || binary.LittleEndian.Uint16(b[22:]) != 2 {
		t.Fatal("not a stereo WAV")
	}
	frame := func(i int) (int16, int16) {
		off := 44 + i*4
		return int16(binary.LittleEndian.Uint16(b[off:])), int16(binary.LittleEndian.Uint16(b[off+2:]))
	}
	if l, r := frame(10); l != 1000 || r != 0 {
		t.Fatalf("frame 10: %d %d", l, r)
	}
	if l, r := frame(4010); l != 0 || r != 1000 {
		t.Fatalf("frame 4010: %d %d", l, r)
	}
	if l, _ := frame(8010); l != 1000 {
		t.Fatalf("frame 8010: %d", l)
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*", "*", "*", "*.raw")); len(matches) != 0 {
		t.Fatalf("temp files left: %v", matches)
	}
}

func TestRecorderWithNothingIsEmpty(t *testing.T) {
	rec, err := NewRecorder(t.TempDir(), "x/y.wav", time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rec.Finish(); err != ErrEmpty {
		t.Fatalf("err %v", err)
	}
}
