// Package media relays RTP between the two legs of a bridged call and
// keeps a stereo recording of it. It decodes G.711 for the recording and
// the FAS guard. Every other codec is relayed untouched and not recorded.
package media

var (
	ulawTable [256]int16
	alawTable [256]int16
)

func init() {
	for i := 0; i < 256; i++ {
		ulawTable[i] = ulawDecode(byte(i))
		alawTable[i] = alawDecode(byte(i))
	}
}

// DecodeULaw appends 16-bit PCM for mu-law bytes.
func DecodeULaw(dst []int16, src []byte) []int16 {
	for _, b := range src {
		dst = append(dst, ulawTable[b])
	}
	return dst
}

// DecodeALaw appends 16-bit PCM for A-law bytes.
func DecodeALaw(dst []int16, src []byte) []int16 {
	for _, b := range src {
		dst = append(dst, alawTable[b])
	}
	return dst
}

func ulawDecode(u byte) int16 {
	u = ^u
	sign := u & 0x80
	exponent := (u >> 4) & 0x07
	mantissa := u & 0x0F
	sample := (int32(mantissa)<<3 + 0x84) << exponent
	sample -= 0x84
	if sign != 0 {
		return int16(-sample)
	}
	return int16(sample)
}

func alawDecode(a byte) int16 {
	a ^= 0x55
	sign := a & 0x80
	exponent := (a >> 4) & 0x07
	mantissa := int32(a & 0x0F)
	var sample int32
	if exponent == 0 {
		sample = mantissa<<4 + 8
	} else {
		sample = (mantissa<<4 + 0x108) << (exponent - 1)
	}
	if sign == 0 {
		return int16(-sample)
	}
	return int16(sample)
}

// EncodeULaw converts 16-bit PCM to mu-law. Tests and the demo use it to
// build real RTP payloads.
func EncodeULaw(dst []byte, src []int16) []byte {
	for _, s := range src {
		dst = append(dst, ulawEncode(s))
	}
	return dst
}

func ulawEncode(sample int16) byte {
	const bias = 0x84
	const clip = 32635
	s := int32(sample)
	sign := byte(0)
	if s < 0 {
		s = -s
		sign = 0x80
	}
	if s > clip {
		s = clip
	}
	s += bias
	exponent := byte(7)
	for mask := int32(0x4000); s&mask == 0 && exponent > 0; mask >>= 1 {
		exponent--
	}
	mantissa := byte((s >> (exponent + 3)) & 0x0F)
	return ^(sign | exponent<<4 | mantissa)
}
