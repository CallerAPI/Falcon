// Package sipguard drops UDP datagrams whose declared body length the
// datagram cannot hold, before the SIP parser sizes a body from it.
//
// The parser reads Content-Length (or the compact form l) and allocates
// that many bytes for the body. A datagram can only carry what follows its
// header section, so a larger declared length is never valid on UDP. The
// filter walks the header section the way the parser does, including line
// folding, so it sees the same length the parser would see.
package sipguard

import (
	"bytes"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/emiago/sipgo/sip"
)

var dropped atomic.Uint64

// Dropped is the number of datagrams ReadFilter dropped in this process.
func Dropped() uint64 { return dropped.Load() }

// ReadFilter is a sip.TransportReadFilter. On UDP it drops a datagram that
// Drop rejects. Every other transport passes through unchanged.
//
// A drop returns nil data and a nil error. An error stops the UDP read loop
// for the whole listener, so the filter never returns one.
func ReadFilter(info sip.TransportReadProps, data []byte) ([]byte, error) {
	if !strings.EqualFold(info.Transport, "udp") {
		return data, nil
	}
	if Drop(data) {
		dropped.Add(1)
		return nil, nil
	}
	return data, nil
}

// Drop reports whether a datagram must not reach the parser. That is when
// a length header declares more bytes than follow the header section, a
// length value is not a non-negative integer, two length headers disagree,
// or a length header is present and the header section has no end.
//
// The first pass splits lines on CRLF, as the parser does. The second pass
// splits on a bare LF as well, so a length header that hides inside
// another header line by a bare LF is also checked.
func Drop(data []byte) bool {
	return dropSplit(data, splitCRLF) || dropSplit(data, splitLF)
}

type splitter func(data []byte) (lines [][]byte, body []byte, ended bool)

func dropSplit(data []byte, split splitter) bool {
	lines, body, ended := split(data)
	declared, found, bad := declaredLength(lines)
	if bad {
		return true
	}
	if !found {
		return false
	}
	if !ended {
		return true
	}
	return declared > uint64(len(body))
}

// splitCRLF returns the lines before the first CRLFCRLF and the bytes after
// it. With no CRLFCRLF, every line is returned and ended is false.
func splitCRLF(data []byte) ([][]byte, []byte, bool) {
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		return bytes.Split(data, []byte("\r\n")), nil, false
	}
	return bytes.Split(data[:end], []byte("\r\n")), data[end+4:], true
}

// splitLF ends each line at LF and removes one CR before it. The header
// section ends at the first empty line.
func splitLF(data []byte) ([][]byte, []byte, bool) {
	var lines [][]byte
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return append(lines, data), nil, false
		}
		line := bytes.TrimSuffix(data[:i], []byte("\r"))
		data = data[i+1:]
		if len(line) == 0 {
			return lines, data, true
		}
		lines = append(lines, line)
	}
	return lines, nil, false
}

// declaredLength reads every length header in the header lines. lines[0]
// is the start line. The parser does not fold a continuation line into the
// start line, so lines[1] is always a header of its own, also when it
// starts with whitespace.
func declaredLength(lines [][]byte) (n uint64, found, bad bool) {
	for i := 1; i < len(lines); {
		line := lines[i]
		i++
		var conts [][]byte
		for i < len(lines) && len(lines[i]) > 0 && isContinuation(lines[i][0]) {
			conts = append(conts, lines[i])
			i++
		}
		if len(conts) > 0 {
			line = fold(line, conts)
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 || !isLengthName(bytes.TrimSpace(line[:colon])) {
			continue
		}
		v, err := strconv.ParseUint(string(bytes.TrimSpace(line[colon+1:])), 10, 32)
		if err != nil {
			return 0, true, true
		}
		if found && v != n {
			return 0, true, true
		}
		n, found = v, true
	}
	return n, found, false
}

// fold joins continuation lines to their header line the way the sipgo
// parser does: trailing whitespace off the header line, leading and
// trailing whitespace off each continuation, one space between them.
func fold(line []byte, conts [][]byte) []byte {
	out := append([]byte(nil), bytes.TrimRight(line, " \t")...)
	for _, c := range conts {
		out = append(out, ' ')
		out = append(out, bytes.Trim(c, " \t")...)
	}
	return out
}

func isContinuation(c byte) bool { return c == ' ' || c == '\t' }

func isLengthName(name []byte) bool {
	return asciiEqualFold(name, "content-length") || asciiEqualFold(name, "l")
}

func asciiEqualFold(b []byte, lower string) bool {
	if len(b) != len(lower) {
		return false
	}
	for i := range b {
		c := b[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}
