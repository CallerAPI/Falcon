package media

import (
	"errors"
	"strconv"
	"strings"
)

// SDP is the audio part of a session description, plus the lines needed
// to write it back with Falcon's address in place of the far end's.
type SDP struct {
	lines []string
	// Addr and Port are where the far end receives audio.
	Addr string
	Port int
	// Proto is RTP/AVP, RTP/SAVP, and so on.
	Proto string
	// Payloads are the audio payload types in the order offered.
	Payloads []uint8
	// Codecs names each payload type, for example PCMU/8000.
	Codecs map[uint8]string
	// Direction is sendrecv, sendonly, recvonly, or inactive.
	Direction  string
	audioLine  int
	encrypted  bool
	sessionC   int
	mediaC     int
	originLine int
}

// ErrNoAudio means the body has no audio stream Falcon can relay.
var ErrNoAudio = errors.New("sdp: no audio stream")

var staticCodecs = map[uint8]string{
	0: "PCMU/8000", 3: "GSM/8000", 4: "G723/8000", 8: "PCMA/8000",
	9: "G722/8000", 13: "CN/8000", 18: "G729/8000",
}

// ParseSDP reads the first audio stream of an SDP body.
func ParseSDP(body []byte) (*SDP, error) {
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	s := &SDP{Codecs: map[uint8]string{}, audioLine: -1, sessionC: -1, mediaC: -1, originLine: -1, Direction: "sendrecv"}
	section := "session"
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r ")
		if line == "" {
			continue
		}
		idx := len(s.lines)
		s.lines = append(s.lines, line)
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		val := line[2:]
		switch line[0] {
		case 'o':
			s.originLine = idx
		case 'm':
			f := strings.Fields(val)
			section = "other"
			if len(f) >= 3 && f[0] == "audio" && s.audioLine < 0 {
				section = "audio"
				s.audioLine = idx
				s.Port, _ = strconv.Atoi(f[1])
				s.Proto = f[2]
				for _, pt := range f[3:] {
					if n, err := strconv.Atoi(pt); err == nil && n >= 0 && n < 128 {
						s.Payloads = append(s.Payloads, uint8(n))
					}
				}
				if strings.Contains(s.Proto, "SAVP") {
					s.encrypted = true
				}
			}
		case 'c':
			f := strings.Fields(val)
			if len(f) != 3 {
				continue
			}
			switch section {
			case "session":
				s.sessionC = idx
				if s.Addr == "" {
					s.Addr = f[2]
				}
			case "audio":
				s.mediaC = idx
				s.Addr = f[2]
			}
		case 'a':
			if section != "audio" {
				if section == "session" {
					s.direction(val)
				}
				continue
			}
			s.direction(val)
			if strings.HasPrefix(val, "rtpmap:") {
				rest := strings.TrimPrefix(val, "rtpmap:")
				ptText, name, ok := strings.Cut(rest, " ")
				if n, err := strconv.Atoi(ptText); ok && err == nil && n >= 0 && n < 128 {
					s.Codecs[uint8(n)] = strings.TrimSpace(name)
				}
			}
			if strings.HasPrefix(val, "crypto:") {
				s.encrypted = true
			}
		}
	}
	if s.audioLine < 0 || s.Port <= 0 {
		return nil, ErrNoAudio
	}
	for _, pt := range s.Payloads {
		if _, ok := s.Codecs[pt]; !ok {
			if name, ok := staticCodecs[pt]; ok {
				s.Codecs[pt] = name
			}
		}
	}
	return s, nil
}

func (s *SDP) direction(val string) {
	switch val {
	case "sendrecv", "sendonly", "recvonly", "inactive":
		s.Direction = val
	}
}

// Encrypted reports SRTP. Falcon relays it but cannot record or hear it.
func (s *SDP) Encrypted() bool { return s.encrypted }

// Codec is the first audio payload that carries speech. In an answer that
// is the codec the call uses.
func (s *SDP) Codec() (uint8, string) {
	for _, pt := range s.Payloads {
		name := strings.ToUpper(s.Codecs[pt])
		if strings.HasPrefix(name, "TELEPHONE-EVENT") || strings.HasPrefix(name, "CN/") {
			continue
		}
		return pt, s.Codecs[pt]
	}
	return 0, ""
}

// Rewrite returns the body with Falcon's address and port on the audio
// stream. ICE lines and explicit RTCP ports are dropped: RTCP goes to
// port+1. Any other media stream is disabled. preferG711 moves PCMU and
// PCMA to the front of the offer so the far end is likely to pick a codec
// Falcon can record. The far end still chooses.
func (s *SDP) Rewrite(addr string, port int, preferG711 bool) []byte {
	family := "IP4"
	if strings.Contains(addr, ":") {
		family = "IP6"
	}
	var b strings.Builder
	section := "session"
	for i, line := range s.lines {
		if len(line) >= 2 && line[1] == '=' {
			switch line[0] {
			case 'm':
				section = "other"
				if i == s.audioLine {
					section = "audio"
				}
			case 'a':
				val := line[2:]
				if dropAttr(val) {
					continue
				}
			}
		}
		switch {
		case i == s.originLine:
			f := strings.Fields(line[2:])
			if len(f) == 6 {
				f[4], f[5] = family, addr
				line = "o=" + strings.Join(f, " ")
			}
		case i == s.sessionC || i == s.mediaC:
			line = "c=IN " + family + " " + addr
		case i == s.audioLine:
			f := strings.Fields(line[2:])
			pts := s.Payloads
			if preferG711 {
				pts = g711First(pts, s.Codecs)
			}
			out := []string{"audio", strconv.Itoa(port), f[2]}
			for _, pt := range pts {
				out = append(out, strconv.Itoa(int(pt)))
			}
			line = "m=" + strings.Join(out, " ")
		case section == "other" && strings.HasPrefix(line, "m="):
			f := strings.Fields(line[2:])
			if len(f) >= 2 {
				f[1] = "0"
				line = "m=" + strings.Join(f, " ")
			}
		}
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	if s.sessionC < 0 && s.mediaC < 0 {
		// No connection line at all is malformed. Add one at session level.
		return []byte(strings.Replace(b.String(), "\r\nt=", "\r\nc=IN "+family+" "+addr+"\r\nt=", 1))
	}
	return []byte(b.String())
}

func dropAttr(val string) bool {
	for _, p := range []string{"candidate:", "ice-ufrag:", "ice-pwd:", "ice-options:", "end-of-candidates", "rtcp:", "rtcp-mux", "remote-candidates:", "ice-lite"} {
		if strings.HasPrefix(val, p) {
			return true
		}
	}
	return false
}

func g711First(pts []uint8, codecs map[uint8]string) []uint8 {
	out := make([]uint8, 0, len(pts))
	for _, want := range []string{"PCMU/8000", "PCMA/8000"} {
		for _, pt := range pts {
			if strings.EqualFold(codecs[pt], want) {
				out = append(out, pt)
			}
		}
	}
	for _, pt := range pts {
		name := strings.ToUpper(codecs[pt])
		if name != "PCMU/8000" && name != "PCMA/8000" {
			out = append(out, pt)
		}
	}
	return out
}

// Decoder turns one payload into 16-bit PCM at 8 kHz. Nil means Falcon
// cannot decode that payload type and only relays it.
type Decoder func(dst []int16, payload []byte) []int16

// DecoderFor returns the G.711 decoder for a codec name.
func DecoderFor(name string) Decoder {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "PCMU/8000", "PCMU/8000/1":
		return DecodeULaw
	case "PCMA/8000", "PCMA/8000/1":
		return DecodeALaw
	}
	return nil
}
