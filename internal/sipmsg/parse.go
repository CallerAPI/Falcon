package sipmsg

import (
	"strings"
)

const maxMessageBytes = 64 * 1024

var compact = map[string]string{
	"f": "from",
	"t": "to",
	"i": "call-id",
	"m": "contact",
	"v": "via",
	"c": "content-type",
	"l": "content-length",
	"s": "subject",
	"k": "supported",
	"e": "content-encoding",
}

// Message is a parsed SIP request or response.
type Message struct {
	StartLine  string
	Method     string
	RequestURI string
	SIPVersion string
	Headers    map[string][]string
	Body       string
	Raw        string
}

// Parse reads a raw SIP datagram or stream message.
func Parse(raw string) (*Message, error) {
	if len(raw) > maxMessageBytes {
		raw = raw[:maxMessageBytes]
	}
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.Trim(raw, "\x00")
	if strings.TrimSpace(raw) == "" {
		return nil, errEmpty
	}

	headerPart, body, _ := strings.Cut(raw, "\n\n")
	lines := strings.Split(headerPart, "\n")
	if len(lines) == 0 {
		return nil, errEmpty
	}

	m := &Message{
		StartLine: strings.TrimSpace(lines[0]),
		Headers:   make(map[string][]string, 16),
		Body:      body,
		Raw:       raw,
	}
	parseStartLine(m)

	var lastName string
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if lastName != "" {
				vs := m.Headers[lastName]
				vs[len(vs)-1] = vs[len(vs)-1] + " " + strings.TrimSpace(line)
				m.Headers[lastName] = vs
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		lastName = canonicalHeader(name)
		m.Headers[lastName] = append(m.Headers[lastName], strings.TrimSpace(value))
	}
	return m, nil
}

func parseStartLine(m *Message) {
	parts := strings.Fields(m.StartLine)
	if len(parts) < 3 {
		return
	}
	if strings.HasPrefix(parts[0], "SIP/") {
		m.SIPVersion = parts[0]
		return
	}
	m.Method = strings.ToUpper(parts[0])
	m.RequestURI = parts[1]
	m.SIPVersion = parts[2]
}

func canonicalHeader(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if full, ok := compact[n]; ok {
		return full
	}
	return n
}

// Get returns the first header value, or empty.
func (m *Message) Get(name string) string {
	if m == nil {
		return ""
	}
	vs := m.Headers[canonicalHeader(name)]
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// All returns every value for a header.
func (m *Message) All(name string) []string {
	if m == nil {
		return nil
	}
	return m.Headers[canonicalHeader(name)]
}
