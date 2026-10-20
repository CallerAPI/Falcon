package media

import "encoding/binary"

// Packet is the part of an RTP header the relay and the recorder read.
type Packet struct {
	Marker      bool
	PayloadType uint8
	Sequence    uint16
	Timestamp   uint32
	SSRC        uint32
	Payload     []byte
}

const rtpHeaderLen = 12

// ParseRTP decodes one RTP packet. It skips CSRCs, a header extension,
// and padding. The payload aliases b.
func ParseRTP(b []byte) (Packet, bool) {
	var p Packet
	if len(b) < rtpHeaderLen || b[0]>>6 != 2 {
		return p, false
	}
	cc := int(b[0] & 0x0F)
	p.Marker = b[1]&0x80 != 0
	p.PayloadType = b[1] & 0x7F
	p.Sequence = binary.BigEndian.Uint16(b[2:])
	p.Timestamp = binary.BigEndian.Uint32(b[4:])
	p.SSRC = binary.BigEndian.Uint32(b[8:])
	off := rtpHeaderLen + cc*4
	if len(b) < off {
		return p, false
	}
	if b[0]&0x10 != 0 {
		if len(b) < off+4 {
			return p, false
		}
		off += 4 + int(binary.BigEndian.Uint16(b[off+2:]))*4
		if len(b) < off {
			return p, false
		}
	}
	end := len(b)
	if b[0]&0x20 != 0 && end > off {
		if pad := int(b[end-1]); pad <= end-off {
			end -= pad
		}
	}
	p.Payload = b[off:end]
	return p, true
}

// BuildRTP encodes a packet with no CSRCs and no extension.
func BuildRTP(p Packet) []byte {
	out := make([]byte, rtpHeaderLen+len(p.Payload))
	out[0] = 0x80
	out[1] = p.PayloadType & 0x7F
	if p.Marker {
		out[1] |= 0x80
	}
	binary.BigEndian.PutUint16(out[2:], p.Sequence)
	binary.BigEndian.PutUint32(out[4:], p.Timestamp)
	binary.BigEndian.PutUint32(out[8:], p.SSRC)
	copy(out[rtpHeaderLen:], p.Payload)
	return out
}

// RTCP packets carry payload type 200 to 211 in the second byte. RFC 5761
// uses that range to tell them apart from RTP on one port.
func isRTCP(b []byte) bool {
	return len(b) >= 2 && b[1] >= 192 && b[1] <= 223
}
