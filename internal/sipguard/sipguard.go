// Package sipguard holds input checks that run on raw SIP bytes before the
// sipgo parser sees them.
package sipguard

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/emiago/sipgo/sip"
)

// TransportLayerOption installs the read filter on every transport of a
// sipgo transport layer. sipgo.WithUserAgentTransportLayerOptions replaces
// the options of an earlier call, so pass this one in the same call as the
// other transport layer options.
func TransportLayerOption() sip.TransportLayerOption {
	return sip.WithTransportLayerReadFilter(ReadFilter)
}

// ReadFilter drops a UDP datagram that DatagramBodyOverflows flags. The
// sipgo v1.6.0 module allocates the declared body size before it checks it,
// so a small datagram can force a 4 GiB allocation. The pinned sipgo bounds
// that allocation by the message size. The filter stays so a dependency
// change cannot bring the allocation back. The parser rejects such a
// datagram as incomplete anyway.
//
// Stream transports pass through: the filter sees chunks there, not whole
// messages, and the stream parser bounds the body on its own.
//
// A dropped datagram returns no bytes and no error. An error stops the
// sipgo UDP read loop.
func ReadFilter(info sip.TransportReadProps, data []byte) ([]byte, error) {
	if !strings.EqualFold(info.Transport, "udp") {
		return data, nil
	}
	if DatagramBodyOverflows(data) {
		return nil, nil
	}
	return data, nil
}

// DatagramBodyOverflows reports whether data must be dropped before the
// sipgo parser reads a body length from it. That is true when a
// Content-Length (or its compact form "l") is larger than the bytes after
// the header block, does not parse as a non-negative integer, or disagrees
// with another length header. It is also true when a length header is
// present but no header end is found.
//
// Headers are unfolded the way sipgo unfolds them: a line that starts with
// a space or a tab continues the header above it. The check runs twice.
// The first pass ends lines at CRLF only, as sipgo v1.6.0 does. The second
// pass also ends lines at a bare LF, so a parser that accepts LF line
// endings cannot see a length header that the first pass missed.
func DatagramBodyOverflows(data []byte) bool {
	return lengthUnsafe(data, false) || lengthUnsafe(data, true)
}

func lengthUnsafe(data []byte, bareLF bool) bool {
	headers, available, complete := headerBlock(data, bareLF)
	var (
		declared uint64
		seen     bool
	)
	for _, h := range headers {
		name, value, ok := bytes.Cut(h, []byte(":"))
		if !ok || !isLengthHeader(bytes.TrimSpace(name)) {
			continue
		}
		if !complete {
			return true
		}
		n, err := strconv.ParseUint(string(bytes.TrimSpace(value)), 10, 64)
		if err != nil || n > uint64(available) || (seen && n != declared) {
			return true
		}
		declared, seen = n, true
	}
	return false
}

func isLengthHeader(name []byte) bool {
	return bytes.EqualFold(name, []byte("Content-Length")) || bytes.EqualFold(name, []byte("l"))
}

// headerBlock returns the unfolded header lines after the start line and
// the number of bytes after the empty line that ends them. complete is
// false when data has no empty line. The headers read so far are still
// returned then.
func headerBlock(data []byte, bareLF bool) (headers [][]byte, available int, complete bool) {
	line, n, ok := nextLine(data, bareLF)
	if !ok {
		return nil, 0, false
	}
	pos := n
	for pos < len(data) {
		line, n, ok = nextLine(data[pos:], bareLF)
		if !ok {
			line, n = data[pos:], len(data)-pos
		}
		pos += n
		if ok && len(line) == 0 {
			return headers, len(data) - pos, true
		}
		if isContinuation(line) && len(headers) > 0 {
			last := headers[len(headers)-1]
			folded := make([]byte, 0, len(last)+1+len(line))
			folded = append(folded, bytes.TrimRight(last, " \t")...)
			folded = append(folded, ' ')
			folded = append(folded, bytes.Trim(line, " \t")...)
			headers[len(headers)-1] = folded
			continue
		}
		headers = append(headers, line)
	}
	return headers, 0, false
}

// nextLine returns the first line of data without its line ending and the
// bytes it used. ok is false when no line ending is found.
func nextLine(data []byte, bareLF bool) (line []byte, n int, ok bool) {
	if !bareLF {
		i := bytes.Index(data, []byte("\r\n"))
		if i < 0 {
			return nil, 0, false
		}
		return data[:i], i + 2, true
	}
	i := bytes.IndexByte(data, '\n')
	if i < 0 {
		return nil, 0, false
	}
	return bytes.TrimSuffix(data[:i], []byte("\r")), i + 1, true
}

func isContinuation(line []byte) bool {
	return len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
}
