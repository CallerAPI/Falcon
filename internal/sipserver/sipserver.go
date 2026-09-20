// Package sipserver answers SIP directly, so a switch or SBC with no script
// hook can still route through Falcon.
//
// The switch sends the INVITE here first, the way it would to a redirect
// server. Falcon replies with one final response and is out of the dialog:
// 302 to continue, the reject status (603 by default) to drop. Signaling
// and media stay on the switch. Falcon never sits in the call.
//
// Every class 4 switch and SBC can route through a redirect server with
// configuration only. That covers the platforms that cannot run Lua, AGI,
// or a routing script.
package sipserver

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/callerapi/falcon/internal/httpapi"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/sipmsg"
)

// Screener scores one request. *httpapi.Server satisfies it.
type Screener interface {
	Screen(ctx context.Context, req httpapi.ScreenRequest) (score.Result, error)
}

// Config is the listener setup. Listen empty means off.
type Config struct {
	// Listen is host:port. Falcon binds UDP and TCP on it.
	Listen string
	// Peers may send requests. Anything else is dropped without a reply.
	// Empty allows loopback only.
	Peers []netip.Prefix
	// RedirectHost replaces the host and port of the Request-URI in the
	// Contact of a 302. Empty echoes the Request-URI unchanged.
	RedirectHost string
	// Timeout caps one screening. Past it, the call is allowed.
	Timeout time.Duration
	// Version goes in the Server header.
	Version string
}

// MaxMessage caps one SIP message on the wire.
const MaxMessage = 64 * 1024

// transactionTTL keeps a final response for UDP retransmits (RFC 3261
// Timer H, 32 s).
const transactionTTL = 32 * time.Second

// maxCached bounds the retransmit cache under a flood.
const maxCached = 20000

type cached struct {
	at   time.Time
	resp []byte
}

// Server is one SIP listener over UDP and TCP.
type Server struct {
	cfg      Config
	screener Screener

	udp *net.UDPConn
	tcp net.Listener

	mu     sync.Mutex
	recent map[string]cached

	dropped atomic.Uint64
	sem     chan struct{}
}

// New validates the configuration and binds the sockets, so a bad address
// fails at start and not at the first call.
func New(cfg Config, s Screener) (*Server, error) {
	if strings.TrimSpace(cfg.Listen) == "" {
		return nil, errors.New("sip: empty listen address")
	}
	if s == nil {
		return nil, errors.New("sip: nil screener")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	uaddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("sip: %w", err)
	}
	udp, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, fmt.Errorf("sip udp: %w", err)
	}
	tcp, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("sip tcp: %w", err)
	}
	return &Server{
		cfg:      cfg,
		screener: s,
		udp:      udp,
		tcp:      tcp,
		recent:   make(map[string]cached),
		sem:      make(chan struct{}, 512),
	}, nil
}

// UDPAddr and TCPAddr report the bound addresses. Tests bind port 0.
func (s *Server) UDPAddr() net.Addr { return s.udp.LocalAddr() }
func (s *Server) TCPAddr() net.Addr { return s.tcp.Addr() }

// Serve runs both listeners until ctx ends.
func (s *Server) Serve(ctx context.Context) error {
	go s.serveUDP(ctx)
	go s.serveTCP(ctx)
	go s.sweep(ctx)
	<-ctx.Done()
	_ = s.udp.Close()
	_ = s.tcp.Close()
	return nil
}

// Dropped counts requests from peers outside the allowlist.
func (s *Server) Dropped() uint64 { return s.dropped.Load() }

func (s *Server) allowed(peer netip.Addr) bool {
	peer = peer.Unmap()
	if len(s.cfg.Peers) == 0 {
		return peer.IsLoopback()
	}
	for _, p := range s.cfg.Peers {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

func (s *Server) serveUDP(ctx context.Context) {
	buf := make([]byte, MaxMessage+1)
	for {
		n, peer, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if n > MaxMessage {
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		go func() {
			defer func() { <-s.sem }()
			s.handle(ctx, raw, peer, "UDP", func(resp []byte) {
				_, _ = s.udp.WriteToUDPAddrPort(resp, peer)
			})
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context) {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go s.serveConn(ctx, conn)
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	peer, ok := peerOf(conn.RemoteAddr())
	if !ok || !s.allowed(peer.Addr()) {
		s.dropped.Add(1)
		return
	}
	rd := bufio.NewReaderSize(conn, 16*1024)
	var wmu sync.Mutex
	write := func(resp []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write(resp)
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		raw, err := readFrame(rd)
		if err != nil {
			return
		}
		s.handle(ctx, raw, peer, "TCP", write)
	}
}

// readFrame reads one SIP message from a stream: headers to the blank
// line, then Content-Length bytes of body. Keep-alive CRLFs are skipped.
func readFrame(rd *bufio.Reader) ([]byte, error) {
	var head strings.Builder
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if head.Len() == 0 && strings.TrimSpace(line) == "" {
			continue
		}
		head.WriteString(line)
		if head.Len() > MaxMessage {
			return nil, errors.New("sip: headers too large")
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	h := head.String()
	clen := 0
	for _, l := range strings.Split(h, "\n") {
		name, val, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "content-length" || n == "l" {
			clen, _ = strconv.Atoi(strings.TrimSpace(val))
			break
		}
	}
	if clen < 0 || clen > MaxMessage {
		return nil, errors.New("sip: bad content-length")
	}
	body := make([]byte, clen)
	if _, err := io.ReadFull(rd, body); err != nil {
		return nil, err
	}
	return append([]byte(h), body...), nil
}

func peerOf(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.AddrPort(), true
	case *net.TCPAddr:
		return v.AddrPort(), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}

// handle answers one request. write sends bytes back to the peer.
func (s *Server) handle(ctx context.Context, raw []byte, peer netip.AddrPort, transport string, write func([]byte)) {
	if !s.allowed(peer.Addr()) {
		n := s.dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			log.Printf("falcon sip: dropped %d requests from peers outside FALCON_SIP_PEERS (last %s)", n, peer.Addr())
		}
		return
	}
	msg, err := sipmsg.Parse(string(raw))
	if err != nil || msg.Method == "" {
		return
	}
	switch msg.Method {
	case "INVITE":
		s.handleInvite(ctx, msg, peer, transport, write)
	case "ACK":
		// ACK to a non-2xx final is hop by hop and needs no reply.
	case "CANCEL":
		if _, ok := s.lookup(transactionKey(msg, "INVITE")); ok {
			write(s.response(msg, 200, "OK", nil, ""))
		} else {
			write(s.response(msg, 481, "Call/Transaction Does Not Exist", nil, ""))
		}
	case "OPTIONS":
		write(s.response(msg, 200, "OK", map[string]string{"Accept": "application/sdp"}, ""))
	default:
		write(s.response(msg, 405, "Method Not Allowed", nil, ""))
	}
}

func (s *Server) handleInvite(ctx context.Context, msg *sipmsg.Message, peer netip.AddrPort, transport string, write func([]byte)) {
	key := transactionKey(msg, "INVITE")
	if resp, ok := s.lookup(key); ok {
		write(resp)
		return
	}
	write(s.response(msg, 100, "Trying", nil, ""))

	sctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	req := httpapi.ScreenRequest{
		RawSIP:     msg.Raw,
		SourceIP:   sourceIP(msg, peer.Addr()),
		SourcePort: int(peer.Port()),
		Switch:     "sip/" + peer.Addr().Unmap().String(),
	}
	result, err := s.screener.Screen(sctx, req)
	if err != nil {
		// Fail open, the same as the HTTP API.
		result = score.Result{Action: score.ActionAllow, Headers: map[string]string{"X-Falcon-Action": "allow", "X-Falcon-Error": err.Error()}}
	}

	status, reason, contact := s.decide(result, msg.RequestURI)
	resp := s.response(msg, status, reason, result.Headers, contact)
	s.remember(key, resp)
	write(resp)
}

// decide maps the action to the SIP answer. A redirect server owns no
// authentication, so challenge is a reject here.
func (s *Server) decide(r score.Result, ruri string) (int, string, string) {
	switch r.Action {
	case score.ActionReject, score.ActionChallenge:
		status, reason := r.SIPStatus, r.SIPReason
		if status < 300 || status == 407 {
			status, reason = 603, "Decline"
		}
		if reason == "" {
			reason = "Decline"
		}
		return status, reason, ""
	default:
		return 302, "Moved Temporarily", redirectContact(ruri, s.cfg.RedirectHost)
	}
}

// response builds one SIP response for a request: Via copied, To tagged,
// then the X-Falcon-* headers and an optional Contact.
func (s *Server) response(req *sipmsg.Message, status int, reason string, extra map[string]string, contact string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", status, reason)
	for _, v := range req.All("Via") {
		b.WriteString("Via: ")
		b.WriteString(v)
		b.WriteString("\r\n")
	}
	if from := req.Get("From"); from != "" {
		b.WriteString("From: ")
		b.WriteString(from)
		b.WriteString("\r\n")
	}
	if to := req.Get("To"); to != "" {
		b.WriteString("To: ")
		b.WriteString(to)
		if status > 100 && !strings.Contains(strings.ToLower(to), ";tag=") {
			b.WriteString(";tag=")
			b.WriteString(tag())
		}
		b.WriteString("\r\n")
	}
	if cid := req.Get("Call-ID"); cid != "" {
		b.WriteString("Call-ID: ")
		b.WriteString(cid)
		b.WriteString("\r\n")
	}
	if cseq := req.Get("CSeq"); cseq != "" {
		b.WriteString("CSeq: ")
		b.WriteString(cseq)
		b.WriteString("\r\n")
	}
	if contact != "" {
		b.WriteString("Contact: ")
		b.WriteString(contact)
		b.WriteString("\r\n")
	}
	b.WriteString("Allow: INVITE, ACK, CANCEL, OPTIONS\r\n")
	if s.cfg.Version != "" {
		b.WriteString("Server: Falcon/")
		b.WriteString(s.cfg.Version)
		b.WriteString("\r\n")
	}
	for k, v := range extra {
		if v == "" || (!strings.HasPrefix(k, "X-Falcon-") && k != "Accept") {
			continue
		}
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(sanitize(v))
		b.WriteString("\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return []byte(b.String())
}

// sourceIP is the address the switch would report: an explicit
// X-Source-IP, else the hop below the switch in Via, else the peer.
func sourceIP(m *sipmsg.Message, peer netip.Addr) string {
	if v := strings.TrimSpace(m.Get("X-Source-IP")); v != "" {
		return sipmsg.HostOnly(v)
	}
	hops := viaHops(m.All("Via"))
	if len(hops) >= 2 {
		if ip := viaAddr(hops[1]); ip != "" {
			return ip
		}
	}
	return peer.Unmap().String()
}

// viaHops flattens comma separated Via values into one hop per entry.
func viaHops(vias []string) []string {
	var out []string
	for _, v := range vias {
		for _, hop := range strings.Split(v, ",") {
			hop = strings.TrimSpace(hop)
			if hop != "" {
				out = append(out, hop)
			}
		}
	}
	return out
}

// viaAddr returns received= when present, else the sent-by host.
func viaAddr(hop string) string {
	params := strings.Split(hop, ";")
	for _, p := range params[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(k, "received") {
			return sipmsg.HostOnly(v)
		}
	}
	fields := strings.Fields(params[0])
	if len(fields) < 2 {
		return ""
	}
	return sipmsg.HostOnly(fields[1])
}

// redirectContact wraps the Request-URI for a 302. With a host, the
// host and port are replaced and user and parameters are kept.
func redirectContact(ruri, host string) string {
	ruri = strings.TrimSpace(ruri)
	if host == "" {
		return "<" + ruri + ">"
	}
	scheme, rest, ok := strings.Cut(ruri, ":")
	if !ok {
		return "<" + ruri + ">"
	}
	user := ""
	if i := strings.Index(rest, "@"); i >= 0 {
		user = rest[:i+1]
		rest = rest[i+1:]
	}
	tail := ""
	if i := strings.IndexAny(rest, ";?"); i >= 0 {
		tail = rest[i:]
	}
	return "<" + scheme + ":" + user + host + tail + ">"
}

// transactionKey follows RFC 3261 17.2.3: top Via branch plus method.
func transactionKey(m *sipmsg.Message, method string) string {
	vias := m.All("Via")
	branch := ""
	if len(vias) > 0 {
		for _, p := range strings.Split(vias[0], ";")[1:] {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(k, "branch") {
				branch = v
				break
			}
		}
	}
	if branch == "" {
		branch = m.Get("Call-ID") + "|" + m.Get("CSeq")
	}
	return branch + "|" + method
}

func (s *Server) lookup(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.recent[key]
	if !ok || time.Since(c.at) > transactionTTL {
		return nil, false
	}
	return c.resp, true
}

func (s *Server) remember(key string, resp []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.recent) >= maxCached {
		now := time.Now()
		for k, c := range s.recent {
			if now.Sub(c.at) > transactionTTL {
				delete(s.recent, k)
			}
		}
		if len(s.recent) >= maxCached {
			return
		}
	}
	s.recent[key] = cached{at: time.Now(), resp: resp}
}

func (s *Server) sweep(ctx context.Context) {
	t := time.NewTicker(transactionTTL)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			now := time.Now()
			for k, c := range s.recent {
				if now.Sub(c.at) > transactionTTL {
					delete(s.recent, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

func tag() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// sanitize keeps a header value on one line.
func sanitize(v string) string {
	v = strings.ReplaceAll(v, "\r", " ")
	v = strings.ReplaceAll(v, "\n", " ")
	return strings.TrimSpace(v)
}

// ParsePeers reads a comma separated list of IPs and CIDRs.
func ParsePeers(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("sip peers: %q is not an IP or CIDR", item)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
