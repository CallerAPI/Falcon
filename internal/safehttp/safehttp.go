// Package safehttp builds HTTP clients for URLs that come from untrusted
// input, such as the x5u in a PASSporT. Every connection is checked at dial
// time against the address actually being connected to, so DNS rebinding and
// redirects cannot reach loopback, link-local, private, or metadata ranges.
// Falcon runs inside carrier networks. A request from a stranger's SIP
// header must never be able to touch the switch, the SBC, or the cloud
// metadata service from the inside.
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Policy describes what an untrusted URL may reach.
type Policy struct {
	// AllowHTTP permits plain http. Lab rigs only.
	AllowHTTP bool
	// AllowPrivate permits private and loopback targets. Tests only.
	AllowPrivate bool
	// MaxRedirects bounds redirect following. Zero disables redirects.
	MaxRedirects int
	// Timeout bounds the whole request.
	Timeout time.Duration
	// MaxBody bounds the response body the caller will read.
	MaxBody int64
}

// DefaultPolicy is what production uses.
func DefaultPolicy() Policy {
	return Policy{MaxRedirects: 2, Timeout: 4 * time.Second, MaxBody: 64 * 1024}
}

var (
	ErrScheme  = errors.New("url scheme is not allowed")
	ErrHost    = errors.New("url host is not allowed")
	ErrPrivate = errors.New("destination address is not public")
	ErrPort    = errors.New("destination port is not allowed")
)

// ValidateURL checks the parts of a URL that can be checked before a
// connection: scheme, presence of a host, and literal addresses.
func (p Policy) ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !p.AllowHTTP {
			return nil, ErrScheme
		}
	default:
		return nil, ErrScheme
	}
	host := u.Hostname()
	if host == "" || u.User != nil {
		return nil, ErrHost
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") || strings.HasSuffix(strings.ToLower(host), ".local") || strings.HasSuffix(strings.ToLower(host), ".internal") {
		if !p.AllowPrivate {
			return nil, ErrHost
		}
	}
	if port := u.Port(); port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return nil, ErrPort
		}
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if !p.AllowPrivate && !IsPublic(addr) {
			return nil, ErrPrivate
		}
	}
	return u, nil
}

// IsPublic reports whether an address is globally routable and not one of
// the ranges an attacker uses to reach infrastructure from the inside.
func IsPublic(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	for _, block := range blocked {
		if block.Contains(a) {
			return false
		}
	}
	return true
}

var blocked = func() []netip.Prefix {
	out := []netip.Prefix{}
	for _, s := range []string{
		"0.0.0.0/8",          // this network
		"100.64.0.0/10",      // carrier NAT
		"169.254.0.0/16",     // link local and cloud metadata
		"192.0.0.0/24",       // IETF protocol assignments
		"192.0.2.0/24",       // documentation
		"198.18.0.0/15",      // benchmarking
		"198.51.100.0/24",    // documentation
		"203.0.113.0/24",     // documentation
		"224.0.0.0/4",        // multicast
		"240.0.0.0/4",        // reserved
		"255.255.255.255/32", // broadcast
		"::/128",
		"::1/128",
		"64:ff9b::/96",  // NAT64
		"100::/64",      // discard
		"2001:db8::/32", // documentation
		"fc00::/7",      // unique local
		"fe80::/10",     // link local
		"ff00::/8",      // multicast
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Client returns an *http.Client that enforces the policy on every hop.
func (p Policy) Client() *http.Client {
	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			if p.AllowPrivate {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if !IsPublic(addr) {
				return fmt.Errorf("%w: %s", ErrPrivate, addr)
			}
			return nil
		},
	}
	transport := &http.Transport{
		Proxy:                 nil, // never use environment proxies for untrusted fetches
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		MaxIdleConns:          64,
		IdleConnTimeout:       60 * time.Second,
		DisableCompression:    true, // the caller caps the body; no decompression bombs
		ForceAttemptHTTP2:     true,
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > p.MaxRedirects {
				return errors.New("too many redirects")
			}
			_, err := p.ValidateURL(req.URL.String())
			return err
		},
	}
}

// Get fetches an untrusted URL and returns up to MaxBody bytes. It validates
// the URL, follows at most MaxRedirects safe hops, and rejects private
// destinations at dial time.
func (p Policy) Get(ctx context.Context, client *http.Client, raw string, accept string) ([]byte, int, error) {
	u, err := p.ValidateURL(raw)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", "CallerAPI-Falcon/1.0 (+https://callerapi.com)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	max := p.MaxBody
	if max <= 0 {
		max = 64 * 1024
	}
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	var total int64
	for {
		n, rerr := resp.Body.Read(chunk)
		if n > 0 {
			total += int64(n)
			if total > max {
				return nil, resp.StatusCode, fmt.Errorf("response exceeds %d bytes", max)
			}
			buf = append(buf, chunk[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	return buf, resp.StatusCode, nil
}
