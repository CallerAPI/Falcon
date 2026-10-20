// Package bridge is Falcon's own SIP and audio path, in the Falcon binary.
//
// The operator adds Falcon to the switch twice: as a carrier at the front
// of the route, and as a customer whose routes are the real vendors. Each
// INVITE is screened once. A clean call gets 503 before answer, the switch
// moves to its next vendor, and Falcon is out of the call. A call worth
// hearing is bridged back to the switch that sent it, or to a vendor named
// by a tech prefix. Falcon relays the audio, records both sides in stereo,
// and listens for false answer supervision.
//
// The bridge never creates a false answer of its own. It answers the
// switch only after the far end answers, passes ringing and early audio,
// ends one leg the moment the other ends, ends a call whose audio stops,
// and caps every call's length.
package bridge

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/callerapi/falcon/internal/httpapi"
	"github.com/callerapi/falcon/internal/media"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// Screener scores an INVITE. *httpapi.Server satisfies it.
type Screener interface {
	Screen(ctx context.Context, req httpapi.ScreenRequest) (score.Result, error)
}

// Controls are the runtime settings read on each call. *httpapi.Server
// satisfies it, so a change in the dashboard applies to the next INVITE.
type Controls interface {
	Mode(ctx context.Context) string
	FASMode(ctx context.Context) string
	Sampling(ctx context.Context) (fanoutEvery, cleanEvery int)
}

// Sink takes a finished recording into the voice pipeline.
type Sink interface {
	IngestRecording(ctx context.Context, rec media.Recording)
}

// CallLog keeps bridged calls and reads routes. *store.SQLite satisfies it.
type CallLog interface {
	InsertMediaCall(ctx context.Context, m store.MediaCall) (int64, error)
	UpdateMediaCall(ctx context.Context, m store.MediaCall) error
	Routes(ctx context.Context) ([]store.Route, error)
	EventByCallID(ctx context.Context, callID string) (store.Event, bool, error)
	NoteReason(ctx context.Context, eventID int64, reason score.Reason) error
	SetOutcome(ctx context.Context, callID string, o store.Outcome) (store.Event, error)
}

// Config is the bridge setup.
type Config struct {
	Listen         string
	Peers          []netip.Prefix
	MediaIP        string
	RTPPortMin     int
	RTPPortMax     int
	MaxCalls       int
	MaxDuration    time.Duration
	RTPTimeout     time.Duration
	ScreenTimeout  time.Duration
	RecordingsDir  string
	RecordMax      int
	FASHold        time.Duration
	FASMaxRingback time.Duration
	// PassStatus is the answer to a call Falcon does not carry. 503 makes
	// every switch move to the next vendor.
	PassStatus int
	Version    string
	InstallID  string
}

// Server is the bridge.
type Server struct {
	cfg    Config
	screen Screener
	ctl    Controls
	sink   Sink
	calls  CallLog
	policy Policy
	routes routeTable
	ports  *media.Allocator

	ua  *sipgo.UserAgent
	srv *sipgo.Server
	cli *sipgo.Client
	dua *sipgo.DialogUA

	udp net.PacketConn
	tcp net.Listener

	mu      sync.Mutex
	byID    map[string]*call
	pending map[string]time.Time
	active  atomic.Int64
	dropped atomic.Uint64
	local   sync.Map
	ctx     context.Context
	wg      sync.WaitGroup
}

// New binds the SIP sockets so a bad address fails at start.
func New(cfg Config, screen Screener, ctl Controls, sink Sink, calls CallLog) (*Server, error) {
	if screen == nil || ctl == nil || calls == nil {
		return nil, errors.New("bridge: screener, controls, and call log are required")
	}
	if cfg.PassStatus < 400 || cfg.PassStatus > 699 {
		cfg.PassStatus = 503
	}
	if cfg.ScreenTimeout <= 0 {
		cfg.ScreenTimeout = 2 * time.Second
	}
	if cfg.MaxCalls <= 0 {
		cfg.MaxCalls = 1000
	}
	s := &Server{
		cfg: cfg, screen: screen, ctl: ctl, sink: sink, calls: calls,
		ports:   media.NewAllocator("", cfg.RTPPortMin, cfg.RTPPortMax),
		byID:    map[string]*call{},
		pending: map[string]time.Time{},
	}
	udp, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("bridge udp: %w", err)
	}
	tcp, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("bridge tcp: %w", err)
	}
	s.udp, s.tcp = udp, tcp
	quiet := slog.New(slog.NewTextHandler(logWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	ua, err := sipgo.NewUA(
		sipgo.WithUserAgent("Falcon/"+cfg.Version),
		sipgo.WithUserAgentTransactionLayerOptions(sip.WithTransactionLayerLogger(quiet)),
		sipgo.WithUserAgentTransportLayerOptions(sip.WithTransportLayerLogger(quiet)),
	)
	if err != nil {
		s.closeSockets()
		return nil, err
	}
	srv, err := sipgo.NewServer(ua, sipgo.WithServerLogger(quiet))
	if err != nil {
		s.closeSockets()
		return nil, err
	}
	host, port := s.viaAddr()
	cli, err := sipgo.NewClient(ua, sipgo.WithClientLogger(quiet), sipgo.WithClientHostname(host), sipgo.WithClientPort(port), sipgo.WithClientConnectionAddr(udp.LocalAddr().String()))
	if err != nil {
		s.closeSockets()
		return nil, err
	}
	s.ua, s.srv, s.cli = ua, srv, cli
	s.dua = &sipgo.DialogUA{Client: cli, ContactHDR: sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: "falcon", Host: host, Port: port}}}
	srv.OnInvite(s.onInvite)
	srv.OnAck(s.onAck)
	srv.OnBye(s.onBye)
	srv.OnOptions(s.onOptions)
	srv.OnUpdate(s.onInDialog)
	srv.OnInfo(s.onInDialog)
	srv.OnNotify(s.onInDialog)
	srv.OnCancel(func(req *sip.Request, tx sip.ServerTransaction) {
		// A CANCEL that matched an INVITE was answered by the transaction
		// layer. This one matched nothing.
		_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
	})
	return s, nil
}

func (s *Server) closeSockets() {
	if s.udp != nil {
		_ = s.udp.Close()
	}
	if s.tcp != nil {
		_ = s.tcp.Close()
	}
}

// logWriter sends sipgo errors to the process log.
type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) {
	log.Printf("falcon bridge: %s", strings.TrimSpace(string(p)))
	return len(p), nil
}

// Serve runs until ctx ends, then hangs up every bridged call on both
// legs so nothing stays billed after a restart.
func (s *Server) Serve(ctx context.Context) error {
	s.ctx = ctx
	if err := s.ReloadRoutes(ctx); err != nil {
		log.Printf("falcon bridge: routes: %v", err)
	}
	go func() { _ = s.srv.ServeUDP(s.udp) }()
	go func() { _ = s.srv.ServeTCP(s.tcp) }()
	go s.sweep(ctx)
	<-ctx.Done()
	s.mu.Lock()
	calls := make([]*call, 0, len(s.byID))
	seen := map[*call]bool{}
	for _, c := range s.byID {
		if !seen[c] {
			seen[c] = true
			calls = append(calls, c)
		}
	}
	s.mu.Unlock()
	for _, c := range calls {
		c.hangup("shutdown")
	}
	s.wg.Wait()
	s.closeSockets()
	_ = s.ua.Close()
	return nil
}

// Active is how many calls are bridged now.
func (s *Server) Active() int { return int(s.active.Load()) }

// Capacity is how many calls the port range and the cap allow.
func (s *Server) Capacity() int {
	byPorts := s.ports.Capacity() / 2
	if s.cfg.MaxCalls < byPorts {
		return s.cfg.MaxCalls
	}
	return byPorts
}

// Dropped counts requests from addresses outside the peer list.
func (s *Server) Dropped() uint64 { return s.dropped.Load() }

// UDPAddr is the bound SIP address. Tests bind port 0.
func (s *Server) UDPAddr() net.Addr { return s.udp.LocalAddr() }

// ReloadRoutes rereads vendor routes from the store.
func (s *Server) ReloadRoutes(ctx context.Context) error {
	routes, err := s.calls.Routes(ctx)
	if err != nil {
		return err
	}
	s.routes.set(routes)
	return nil
}

func (s *Server) allowed(addr netip.Addr) bool {
	addr = addr.Unmap()
	if len(s.cfg.Peers) == 0 {
		return addr.IsLoopback()
	}
	for _, p := range s.cfg.Peers {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func peerAddr(req *sip.Request) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(req.Source())
	return ap, err == nil
}

func (s *Server) admit(req *sip.Request) (netip.AddrPort, bool) {
	ap, ok := peerAddr(req)
	if !ok || !s.allowed(ap.Addr()) {
		n := s.dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			log.Printf("falcon bridge: dropped %d requests from addresses outside FALCON_SIP_PEERS (last %s)", n, req.Source())
		}
		return ap, false
	}
	return ap, true
}

func (s *Server) onOptions(req *sip.Request, tx sip.ServerTransaction) {
	if _, ok := s.admit(req); !ok {
		return
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	res.AppendHeader(sip.NewHeader("Accept", "application/sdp"))
	res.AppendHeader(sip.NewHeader("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS, UPDATE, INFO"))
	_ = tx.Respond(res)
}

// viaAddr is the host and port Falcon names in Via and Contact.
func (s *Server) viaAddr() (string, int) {
	host, portText, _ := net.SplitHostPort(s.udp.LocalAddr().String())
	port, _ := strconv.Atoi(portText)
	if s.cfg.MediaIP != "" {
		return s.cfg.MediaIP, port
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
		return host, port
	}
	return outboundIP(""), port
}

// mediaHost is the address Falcon puts in SDP for a call from peer.
func (s *Server) mediaHost(peer netip.Addr) string {
	if s.cfg.MediaIP != "" {
		return s.cfg.MediaIP
	}
	host, _, _ := net.SplitHostPort(s.udp.LocalAddr().String())
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
		return host
	}
	key := peer.String()
	if v, ok := s.local.Load(key); ok {
		return v.(string)
	}
	ip := outboundIP(key)
	s.local.Store(key, ip)
	return ip
}

// outboundIP is the local address the kernel would use to reach target.
// A UDP dial sends nothing.
func outboundIP(target string) string {
	if target == "" {
		target = "192.0.2.1"
	}
	conn, err := net.Dial("udp", net.JoinHostPort(target, "9"))
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	host, _, _ := net.SplitHostPort(conn.LocalAddr().String())
	return host
}

func (s *Server) register(c *call, ids ...string) {
	s.mu.Lock()
	for _, id := range ids {
		if id != "" {
			s.byID[id] = c
		}
	}
	s.mu.Unlock()
}

func (s *Server) unregister(ids ...string) {
	s.mu.Lock()
	for _, id := range ids {
		delete(s.byID, id)
	}
	s.mu.Unlock()
}

func (s *Server) lookup(callID string) *call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byID[callID]
}

func callIDOf(req *sip.Request) string {
	if h := req.CallID(); h != nil {
		return string(*h)
	}
	return ""
}

func (s *Server) onAck(req *sip.Request, tx sip.ServerTransaction) {
	if c := s.lookup(callIDOf(req)); c != nil {
		c.ack(req, tx)
	}
}

func (s *Server) onBye(req *sip.Request, tx sip.ServerTransaction) {
	c := s.lookup(callIDOf(req))
	if c == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
		return
	}
	c.bye(req, tx)
}

// onInDialog answers UPDATE, INFO, and NOTIFY inside a bridged call. A
// session refresh with SDP gets the leg's current SDP back, so timers on
// either side keep the call up without renegotiating the bridge.
func (s *Server) onInDialog(req *sip.Request, tx sip.ServerTransaction) {
	c := s.lookup(callIDOf(req))
	if c == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
		return
	}
	c.refresh(req, tx)
}

// loopKey is a pending outbound leg's identity. A loop is the switch
// routing Falcon's own outbound leg back to Falcon.
func loopKey(from, to string) string { return from + "\x00" + to }

func (s *Server) markPending(key string) {
	s.mu.Lock()
	s.pending[key] = time.Now()
	s.mu.Unlock()
}

func (s *Server) clearPending(key string) {
	s.mu.Lock()
	delete(s.pending, key)
	s.mu.Unlock()
}

func (s *Server) isLoop(req *sip.Request) bool {
	if h := req.GetHeader("X-Falcon-Leg"); h != nil && strings.HasPrefix(h.Value(), legPrefix(s.cfg.InstallID)) {
		return true
	}
	from, to := "", ""
	if f := req.From(); f != nil {
		from = f.Address.User
	}
	if t := req.To(); t != nil {
		to = t.Address.User
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.pending[loopKey(from, to)]
	return ok && time.Since(at) < 10*time.Second
}

func legPrefix(installID string) string {
	if len(installID) > 8 {
		installID = installID[:8]
	}
	return "f" + installID
}

// sweep forgets loop markers that outlived their call setup.
func (s *Server) sweep(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			for k, at := range s.pending {
				if time.Since(at) > time.Minute {
					delete(s.pending, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

// respond sends a final answer to an INVITE Falcon does not carry, with
// the X-Falcon headers so the switch logs why.
func respond(req *sip.Request, tx sip.ServerTransaction, status int, reason string, headers map[string]string) {
	res := sip.NewResponseFromRequest(req, status, reason, nil)
	for k, v := range headers {
		if strings.HasPrefix(k, "X-Falcon-") && v != "" {
			res.AppendHeader(sip.NewHeader(k, oneLine(v)))
		}
	}
	_ = tx.Respond(res)
}

func oneLine(v string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(v))
}

func reasonPhrase(status int) string {
	switch status {
	case 404:
		return "Not Found"
	case 408:
		return "Request Timeout"
	case 480:
		return "Temporarily Unavailable"
	case 482:
		return "Loop Detected"
	case 483:
		return "Too Many Hops"
	case 486:
		return "Busy Here"
	case 487:
		return "Request Terminated"
	case 488:
		return "Not Acceptable Here"
	case 500:
		return "Server Internal Error"
	case 503:
		return "Service Unavailable"
	case 603:
		return "Decline"
	}
	return "Error"
}
