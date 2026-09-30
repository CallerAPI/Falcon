package sdk

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Core sinks a catalog bridge may name. A new sink is a Falcon release.
// A new plugin that uses a sink already in this list is catalog data.
const (
	SinkVoiceTranscript = "voice.transcript"
)

// Bridge is the catalog description of a plugin that calls one core API.
// It is data. Falcon does not run plugin code.
type Bridge struct {
	Transport string            `json:"transport"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	Sink      string            `json:"sink"`
	Settings  []BridgeSetting   `json:"settings"`
}

// BridgeSetting is one value the operator types on this install.
// Secret values stay in the local database and are not returned.
type BridgeSetting struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Secret  bool   `json:"secret"`
	Pattern string `json:"pattern,omitempty"`
}

var (
	bridgeKey     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	bridgeHeader  = regexp.MustCompile(`^(Authorization|X-[A-Za-z0-9-]{1,32})$`)
	bridgePattern = regexp.MustCompile(`^[ -~]{0,80}$`)
	bridgeHole    = regexp.MustCompile(`\{([a-z][a-z0-9_]{0,31})\}`)
)

// ValidateBridge rejects a catalog bridge that could dial a private host,
// inject a header, or name an unknown core API.
func ValidateBridge(b Bridge) error {
	if b.Transport != "websocket" {
		return fmt.Errorf("transport")
	}
	if b.Sink != SinkVoiceTranscript {
		return fmt.Errorf("sink")
	}
	if len(b.Settings) == 0 || len(b.Settings) > 8 {
		return fmt.Errorf("settings")
	}
	keys := map[string]BridgeSetting{}
	for _, s := range b.Settings {
		if !bridgeKey.MatchString(s.Key) || strings.TrimSpace(s.Label) == "" || len(s.Label) > 40 {
			return fmt.Errorf("setting")
		}
		if _, ok := keys[s.Key]; ok {
			return fmt.Errorf("setting")
		}
		if s.Pattern != "" {
			if !bridgePattern.MatchString(s.Pattern) {
				return fmt.Errorf("pattern")
			}
			if _, err := regexp.Compile(s.Pattern); err != nil {
				return fmt.Errorf("pattern")
			}
		}
		keys[s.Key] = s
	}
	if len(b.Headers) > 4 {
		return fmt.Errorf("headers")
	}
	for name, value := range b.Headers {
		if !bridgeHeader.MatchString(name) {
			return fmt.Errorf("header")
		}
		if err := bridgeTemplate(value, keys); err != nil {
			return err
		}
	}
	return bridgeURL(b.URL, keys)
}

func bridgeTemplate(raw string, keys map[string]BridgeSetting) error {
	if strings.ContainsAny(raw, "\r\n") || len(raw) > 300 {
		return fmt.Errorf("template")
	}
	seen := bridgeHole.FindAllStringSubmatch(raw, -1)
	stripped := bridgeHole.ReplaceAllString(raw, "")
	if strings.Contains(stripped, "{") || strings.Contains(stripped, "}") {
		return fmt.Errorf("template")
	}
	for _, m := range seen {
		if _, ok := keys[m[1]]; !ok {
			return fmt.Errorf("template")
		}
	}
	return nil
}

func bridgeURL(raw string, keys map[string]BridgeSetting) error {
	if err := bridgeTemplate(raw, keys); err != nil {
		return err
	}
	rest := strings.TrimPrefix(raw, "wss://")
	if rest == raw {
		return fmt.Errorf("url")
	}
	hostPart := rest
	if i := strings.IndexAny(hostPart, "/"); i >= 0 {
		hostPart = hostPart[:i]
	}
	if strings.Contains(hostPart, "{") || strings.Contains(hostPart, "}") {
		return fmt.Errorf("url")
	}
	sample := bridgeHole.ReplaceAllString(raw, "x")
	u, err := url.Parse(sample)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("url")
	}
	if u.Scheme != "wss" || u.Hostname() == "" || (u.Port() != "" && u.Port() != "443") {
		return fmt.Errorf("url")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return fmt.Errorf("url")
	}
	if ip := net.ParseIP(host); ip != nil && privateIP(ip) {
		return fmt.Errorf("url")
	}
	return nil
}

func privateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// Materialize fills the URL and headers from operator values.
func (b Bridge) Materialize(values map[string]string) (string, map[string]string, error) {
	if err := ValidateBridge(b); err != nil {
		return "", nil, err
	}
	clean := map[string]string{}
	for _, s := range b.Settings {
		v := strings.TrimSpace(values[s.Key])
		if v == "" {
			return "", nil, fmt.Errorf("missing")
		}
		if strings.ContainsAny(v, "\r\n") || len(v) > 400 {
			return "", nil, fmt.Errorf("value")
		}
		if s.Pattern != "" {
			re, err := regexp.Compile(s.Pattern)
			if err != nil || !re.MatchString(v) {
				return "", nil, fmt.Errorf("value")
			}
		}
		clean[s.Key] = v
	}
	fill := func(raw string) string {
		return bridgeHole.ReplaceAllStringFunc(raw, func(hole string) string {
			key := hole[1 : len(hole)-1]
			return clean[key]
		})
	}
	rawURL := fill(b.URL)
	if err := bridgeURL(rawURL, map[string]BridgeSetting{}); err != nil {
		return "", nil, err
	}
	headers := map[string]string{}
	for name, value := range b.Headers {
		headers[name] = fill(value)
	}
	return rawURL, headers, nil
}
