package bridge

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/httpapi"
	"github.com/callerapi/falcon/internal/media"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// fakeScreen returns a fixed decision and stores the event the way the
// real screener does, so the bridge can join its row by Call-ID.
type fakeScreen struct {
	db     *store.SQLite
	action score.Action
	held   string
	mu     sync.Mutex
	last   httpapi.ScreenRequest
}

func (f *fakeScreen) Screen(ctx context.Context, req httpapi.ScreenRequest) (score.Result, error) {
	f.mu.Lock()
	f.last = req
	f.mu.Unlock()
	callID := ""
	for _, line := range strings.Split(req.RawSIP, "\n") {
		if name, val, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "call-id") {
			callID = strings.TrimSpace(val)
		}
	}
	_, _ = f.db.Insert(ctx, store.Event{ReceivedAt: time.Now().UTC(), Action: f.action, CallID: callID, From: "+13125550188", To: "+14155550100"})
	res := score.Result{Action: f.action, Headers: map[string]string{"X-Falcon-Action": string(f.action)}}
	if f.held != "" {
		res.Action = score.ActionAllow
		res.Headers["X-Falcon-Monitor"] = f.held
	}
	if f.action == score.ActionReject && f.held == "" {
		res.SIPStatus, res.SIPReason = 603, "Decline"
	}
	return res, nil
}

type fakeControls struct {
	mode, fasMode string
	carryAll      bool
}

func (c fakeControls) Mode(context.Context) string         { return c.mode }
func (c fakeControls) FASMode(context.Context) string      { return c.fasMode }
func (c fakeControls) Sampling(context.Context) (int, int) { return 0, 0 }
func (c fakeControls) CarryAll(context.Context) bool       { return c.carryAll }

type captureSink struct {
	mu   sync.Mutex
	recs []media.Recording
}

func (c *captureSink) IngestRecording(_ context.Context, rec media.Recording) {
	c.mu.Lock()
	c.recs = append(c.recs, rec)
	c.mu.Unlock()
}

type harness struct {
	t      *testing.T
	db     *store.SQLite
	br     *Server
	sink   *captureSink
	screen *fakeScreen
	sw     *fakeSwitch
	dir    string
	cancel context.CancelFunc
	done   chan struct{}
}

type options struct {
	action     score.Action
	held       string
	mode       string
	fasMode    string
	rtpTimeout time.Duration
	peers      []netip.Prefix
	carryAll   bool
	direction  string
}

var portBase = 43000

func newHarness(t *testing.T, o options) *harness {
	t.Helper()
	if o.mode == "" {
		o.mode = "enforce"
	}
	if o.fasMode == "" {
		o.fasMode = "monitor"
	}
	if o.rtpTimeout == 0 {
		o.rtpTimeout = 30 * time.Second
	}
	if o.peers == nil {
		o.peers = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	}
	dir := t.TempDir()
	db, err := store.OpenSQLite(filepath.Join(dir, "falcon.db"))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, db: db, sink: &captureSink{}, dir: filepath.Join(dir, "recordings"), done: make(chan struct{})}
	h.screen = &fakeScreen{db: db, action: o.action, held: o.held}
	portBase += 200
	br, err := New(Config{
		Listen: "127.0.0.1:0", Peers: o.peers, MediaIP: "127.0.0.1",
		RTPPortMin: portBase, RTPPortMax: portBase + 199, MaxCalls: 20,
		MaxDuration: time.Hour, RTPTimeout: o.rtpTimeout, ScreenTimeout: time.Second,
		RecordingsDir: h.dir, RecordMax: 120, FASHold: 1500 * time.Millisecond, FASMaxRingback: 2 * time.Second,
		PassStatus: 503, Direction: o.direction, Version: "test", InstallID: "0123456789abcdef",
	}, h.screen, fakeControls{mode: o.mode, fasMode: o.fasMode, carryAll: o.carryAll}, h.sink, db)
	if err != nil {
		t.Fatal(err)
	}
	h.br = br
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { _ = br.Serve(ctx); close(h.done) }()
	h.sw = newFakeSwitch(t)
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(10 * time.Second):
			t.Error("bridge did not stop")
		}
		h.sw.close()
		_ = db.Close()
	})
	time.Sleep(50 * time.Millisecond)
	return h
}

func (h *harness) bridgeAddr() string { return h.br.UDPAddr().String() }

// fakeSwitch is a class 4 switch on loopback: it originates leg A to the
// bridge and terminates the leg the bridge sends back.
type fakeSwitch struct {
	t     *testing.T
	ua    *sipgo.UserAgent
	srv   *sipgo.Server
	cli   *sipgo.Client
	dua   *sipgo.DialogUA
	conn  net.PacketConn
	onB   func(in *inbound)
	legBs chan *inbound
	byes  chan *sip.Request
	mu    sync.Mutex
	dlgB  map[string]*sipgo.DialogServerSession
	dlgA  map[string]*sipgo.DialogClientSession
}

type inbound struct {
	req *sip.Request
	tx  sip.ServerTransaction
	dlg *sipgo.DialogServerSession
}

func newFakeSwitch(t *testing.T) *fakeSwitch {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ua, _ := sipgo.NewUA(sipgo.WithUserAgent("FakeSwitch"))
	srv, _ := sipgo.NewServer(ua)
	_, portText, _ := net.SplitHostPort(conn.LocalAddr().String())
	port, _ := strconv.Atoi(portText)
	cli, _ := sipgo.NewClient(ua, sipgo.WithClientHostname("127.0.0.1"), sipgo.WithClientPort(port), sipgo.WithClientConnectionAddr(conn.LocalAddr().String()))
	sw := &fakeSwitch{
		t: t, ua: ua, srv: srv, cli: cli, conn: conn,
		dua:   &sipgo.DialogUA{Client: cli, ContactHDR: sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: "switch", Host: "127.0.0.1", Port: port}}},
		legBs: make(chan *inbound, 4), byes: make(chan *sip.Request, 8),
		dlgB: map[string]*sipgo.DialogServerSession{}, dlgA: map[string]*sipgo.DialogClientSession{},
	}
	srv.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		dlg, err := sw.dua.ReadInvite(req, tx)
		if err != nil {
			t.Errorf("switch read invite: %v", err)
			return
		}
		sw.mu.Lock()
		sw.dlgB[callIDOf(req)] = dlg
		sw.mu.Unlock()
		in := &inbound{req: req, tx: tx, dlg: dlg}
		sw.legBs <- in
		if sw.onB != nil {
			sw.onB(in)
		}
	})
	srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {
		sw.mu.Lock()
		dlg := sw.dlgB[callIDOf(req)]
		sw.mu.Unlock()
		if dlg != nil {
			_ = dlg.ReadAck(req, tx)
		}
	})
	srv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		sw.mu.Lock()
		b, a := sw.dlgB[callIDOf(req)], sw.dlgA[callIDOf(req)]
		sw.mu.Unlock()
		switch {
		case b != nil:
			_ = b.ReadBye(req, tx)
		case a != nil:
			_ = a.ReadBye(req, tx)
		default:
			_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "No", nil))
		}
		sw.byes <- req
	})
	go func() { _ = srv.ServeUDP(conn) }()
	return sw
}

func (sw *fakeSwitch) close() {
	_ = sw.conn.Close()
	_ = sw.ua.Close()
}

// call sends leg A to the bridge. It returns the dialog and the responses.
func (sw *fakeSwitch) call(ctx context.Context, bridge string, rtpPort int, extra ...sip.Header) (*sipgo.DialogClientSession, []int, error) {
	host, portText, _ := net.SplitHostPort(bridge)
	port, _ := strconv.Atoi(portText)
	req := sip.NewRequest(sip.INVITE, sip.Uri{Scheme: "sip", User: "+14155550100", Host: host, Port: port})
	fromParams := sip.NewParams()
	fromParams.Add("tag", sip.GenerateTagN(8))
	req.AppendHeader(&sip.FromHeader{DisplayName: "Caller", Address: sip.Uri{Scheme: "sip", User: "+13125550188", Host: "127.0.0.1"}, Params: fromParams})
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: "+14155550100", Host: host}, Params: sip.NewParams()})
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.AppendHeader(sip.NewHeader("P-Asserted-Identity", "<sip:+13125550188@127.0.0.1>"))
	for _, h := range extra {
		req.AppendHeader(h)
	}
	req.SetBody(sdpFor(rtpPort))
	dlg, err := sw.dua.WriteInvite(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	sw.mu.Lock()
	sw.dlgA[callIDOf(req)] = dlg
	sw.mu.Unlock()
	var codes []int
	var mu sync.Mutex
	err = dlg.WaitAnswer(ctx, sipgo.AnswerOptions{OnResponse: func(res *sip.Response) error {
		mu.Lock()
		codes = append(codes, res.StatusCode)
		mu.Unlock()
		return nil
	}})
	mu.Lock()
	defer mu.Unlock()
	return dlg, append([]int(nil), codes...), err
}

func sdpFor(port int) []byte {
	return []byte("v=0\r\no=sw 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio " + strconv.Itoa(port) +
		" RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n")
}

// endpoint is one side's RTP socket.
type endpoint struct {
	conn *net.UDPConn
	got  chan int
}

func newEndpoint(t *testing.T) *endpoint {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	e := &endpoint{conn: c, got: make(chan int, 4096)}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			select {
			case e.got <- n:
			default:
			}
		}
	}()
	t.Cleanup(func() { _ = c.Close() })
	return e
}

func (e *endpoint) port() int { return e.conn.LocalAddr().(*net.UDPAddr).Port }

// send plays samples to the bridge port in 20 ms packets at real time.
func (e *endpoint) send(to int, samples []int16, ssrc uint32) {
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: to}
	seq, ts := uint16(1), uint32(0)
	next := time.Now()
	for off := 0; off+160 <= len(samples); off += 160 {
		pkt := media.BuildRTP(media.Packet{PayloadType: 0, Sequence: seq, Timestamp: ts, SSRC: ssrc, Payload: media.EncodeULaw(nil, samples[off:off+160])})
		_, _ = e.conn.WriteToUDP(pkt, dst)
		seq++
		ts += 160
		next = next.Add(20 * time.Millisecond)
		time.Sleep(time.Until(next))
	}
}

func (e *endpoint) received(within time.Duration) int {
	n := 0
	deadline := time.After(within)
	for {
		select {
		case <-e.got:
			n++
		case <-deadline:
			return n
		}
	}
}

func speech(ms int, seed int64) []int16 {
	rng := rand.New(rand.NewSource(seed))
	out := make([]int16, ms*8)
	for i := range out {
		env := 0.35 + 0.65*math.Abs(math.Sin(2*math.Pi*4*float64(i)/8000))
		out[i] = int16(rng.NormFloat64() * 4000 * env)
	}
	return out
}

func ringback(ms int) []int16 {
	out := make([]int16, ms*8)
	for i := range out {
		t := float64(i) / 8000
		out[i] = int16((math.Sin(2*math.Pi*440*t) + math.Sin(2*math.Pi*480*t)) / 2 * 6000)
	}
	return out
}

// sdpPort reads the audio port from an SDP body.
func sdpPort(t *testing.T, body []byte) int {
	s, err := media.ParseSDP(body)
	if err != nil {
		t.Fatalf("sdp: %v\n%s", err, body)
	}
	return s.Port
}

func waitFor(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (h *harness) mediaRow(callID string) store.MediaCall {
	m, _, _ := h.db.MediaCallByCallID(context.Background(), callID)
	return m
}

func answerWith(rtpPort int, ring bool) func(in *inbound) {
	return func(in *inbound) {
		if ring {
			_ = in.dlg.Respond(180, "Ringing", nil)
			time.Sleep(100 * time.Millisecond)
		}
		_ = in.dlg.RespondSDP(sdpFor(rtpPort))
	}
}

func TestBridgeCarriesTheCallAndHangsUpTheFarEndWhenTheCallerLeaves(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dlgA, codes, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err != nil {
		t.Fatalf("leg A: %v (codes %v)", err, codes)
	}
	if len(codes) < 2 || codes[len(codes)-1] != 200 {
		t.Fatalf("leg A responses %v", codes)
	}
	in := <-h.sw.legBs
	if in.req.Recipient.User != "+14155550100" || in.req.From().Address.User != "+13125550188" {
		t.Fatalf("leg B identity: %s from %s", in.req.Recipient.String(), in.req.From().Address.String())
	}
	if in.req.GetHeader("X-Falcon-Leg") == nil || in.req.GetHeader("P-Asserted-Identity") == nil {
		t.Fatal("leg B lacks X-Falcon-Leg or P-Asserted-Identity")
	}
	if in.req.GetHeader("Supported") != nil || in.req.GetHeader("Session-Expires") != nil {
		t.Fatal("leg B carried Supported or Session-Expires")
	}
	bPort := sdpPort(t, in.req.Body())
	aPort := sdpPort(t, dlgA.InviteResponse.Body())
	if aPort == caller.port() || bPort == callee.port() || aPort < portBase || bPort < portBase {
		t.Fatalf("media not anchored on the bridge: a=%d b=%d", aPort, bPort)
	}
	if err := dlgA.Ack(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); caller.send(aPort, speech(1000, 1), 11) }()
	go func() { defer wg.Done(); callee.send(bPort, speech(1000, 2), 22) }()
	wg.Wait()
	if n := callee.received(300 * time.Millisecond); n < 40 {
		t.Fatalf("callee heard %d caller packets", n)
	}
	if n := caller.received(300 * time.Millisecond); n < 40 {
		t.Fatalf("caller heard %d callee packets", n)
	}

	// The caller hangs up. The far end must get a BYE at once.
	byeAt := time.Now()
	if err := dlgA.Bye(ctx); err != nil {
		t.Fatalf("caller bye: %v", err)
	}
	select {
	case bye := <-h.sw.byes:
		if callIDOf(bye) != callIDOf(in.req) {
			t.Fatalf("BYE on the wrong leg: %s", callIDOf(bye))
		}
		if d := time.Since(byeAt); d > time.Second {
			t.Fatalf("far end hung up after %s", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the far end was left up after the caller hung up")
	}

	callID := callIDOf(dlgA.InviteRequest)
	waitFor(t, "row closed", 5*time.Second, func() bool { return h.mediaRow(callID).EndMS > 0 && h.mediaRow(callID).Recording != "" })
	row := h.mediaRow(callID)
	if row.EndedBy != endCaller || row.Status != 200 || row.AnswerMS <= 0 || row.ConnectMS < row.AnswerMS || row.Carry != CarryChallenge || row.Codec != "PCMU/8000" || row.FAS != "" {
		t.Fatalf("row %+v", row)
	}
	path, ok := store.RecordingPath(h.dir, row.Recording)
	if !ok {
		t.Fatalf("recording path %q", row.Recording)
	}
	wav, err := os.ReadFile(path)
	if err != nil || len(wav) < 44 || wav[22] != 2 {
		t.Fatalf("recording is not stereo: %v", err)
	}
	if row.Seconds < 0.9 {
		t.Fatalf("recording is %.2f s", row.Seconds)
	}
	waitFor(t, "sink", 2*time.Second, func() bool { h.sink.mu.Lock(); defer h.sink.mu.Unlock(); return len(h.sink.recs) == 1 })
	ev, _, _ := h.db.EventByCallID(context.Background(), callID)
	if ev.Answered == nil || !*ev.Answered {
		t.Fatalf("outcome not stored on the event: %+v", ev)
	}
	if h.br.Active() != 0 {
		t.Fatalf("active calls %d after hangup", h.br.Active())
	}
}

func TestBridgeHangsUpTheCallerWhenTheFarEndLeaves(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dlgA, _, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err != nil {
		t.Fatal(err)
	}
	_ = dlgA.Ack(ctx)
	in := <-h.sw.legBs
	time.Sleep(200 * time.Millisecond)
	if err := in.dlg.Bye(ctx); err != nil {
		t.Fatalf("far end bye: %v", err)
	}
	select {
	case bye := <-h.sw.byes:
		if callIDOf(bye) != callIDOf(dlgA.InviteRequest) {
			t.Fatalf("BYE on the wrong leg")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the caller was left up after the far end hung up")
	}
	waitFor(t, "row closed", 5*time.Second, func() bool { return h.mediaRow(callIDOf(dlgA.InviteRequest)).EndedBy == endCallee })
}

func TestBridgeCancelsTheFarEndWhenTheCallerCancels(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge})
	caller := newEndpoint(t)
	canceled := make(chan struct{})
	h.sw.onB = func(in *inbound) {
		_ = in.dlg.Respond(180, "Ringing", nil)
		<-in.dlg.Context().Done()
		close(canceled)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-h.sw.legBs
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	_, codes, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err == nil {
		t.Fatalf("leg A answered: %v", codes)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("the far end kept ringing after the caller cancelled")
	}
	waitFor(t, "active zero", 5*time.Second, func() bool { return h.br.Active() == 0 })
}

func TestBridgePassesCleanCallsBeforeAnswer(t *testing.T) {
	h := newHarness(t, options{action: score.ActionAllow})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := h.sw.call(ctx, h.bridgeAddr(), 30000)
	var dr *sipgo.ErrDialogResponse
	if !errors.As(err, &dr) || dr.Res.StatusCode != 503 {
		t.Fatalf("want 503, got %v", err)
	}
	if dr.Res.GetHeader("X-Falcon-Action") == nil {
		t.Fatal("503 lacks the X-Falcon headers")
	}
	select {
	case <-h.sw.legBs:
		t.Fatal("a clean call was bridged")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBridgeRejectsHardBlocksInEnforceMode(t *testing.T) {
	h := newHarness(t, options{action: score.ActionReject})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := h.sw.call(ctx, h.bridgeAddr(), 30000)
	var dr *sipgo.ErrDialogResponse
	if !errors.As(err, &dr) || dr.Res.StatusCode != 603 {
		t.Fatalf("want 603, got %v", err)
	}
}

func TestBridgeRecordsWouldBeRejectsInMonitorMode(t *testing.T) {
	h := newHarness(t, options{action: score.ActionReject, held: "reject", mode: "monitor"})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dlgA, _, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err != nil {
		t.Fatalf("monitor mode must bridge a would-be reject: %v", err)
	}
	_ = dlgA.Ack(ctx)
	<-h.sw.legBs
	_ = dlgA.Bye(ctx)
	waitFor(t, "row", 5*time.Second, func() bool { return h.mediaRow(callIDOf(dlgA.InviteRequest)).Carry == CarryReject })
}

func TestBridgePassesTheFarEndFailureBack(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge})
	h.sw.onB = func(in *inbound) { _ = in.dlg.Respond(486, "Busy Here", nil) }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := h.sw.call(ctx, h.bridgeAddr(), 30000)
	var dr *sipgo.ErrDialogResponse
	if !errors.As(err, &dr) || dr.Res.StatusCode != 486 {
		t.Fatalf("want 486, got %v", err)
	}
	waitFor(t, "active zero", 5*time.Second, func() bool { return h.br.Active() == 0 })
}

func TestBridgeTurnsAnAuthChallengeIntoAPass(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge})
	h.sw.onB = func(in *inbound) { _ = in.dlg.Respond(407, "Proxy Authentication Required", nil) }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := h.sw.call(ctx, h.bridgeAddr(), 30000)
	var dr *sipgo.ErrDialogResponse
	if !errors.As(err, &dr) || dr.Res.StatusCode != 503 {
		t.Fatalf("want 503, got %v", err)
	}
}

func TestBridgeEndsACallWhoseAudioStops(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge, rtpTimeout: 1500 * time.Millisecond})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dlgA, _, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err != nil {
		t.Fatal(err)
	}
	_ = dlgA.Ack(ctx)
	<-h.sw.legBs
	legs := map[string]bool{}
	timeout := time.After(6 * time.Second)
	for len(legs) < 2 {
		select {
		case bye := <-h.sw.byes:
			legs[callIDOf(bye)] = true
		case <-timeout:
			t.Fatalf("silent call not ended on both legs: %v", legs)
		}
	}
	waitFor(t, "row", 5*time.Second, func() bool { return h.mediaRow(callIDOf(dlgA.InviteRequest)).EndedBy == endTimeout })
}

func TestBridgeRefusesItsOwnLegComingBack(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := h.sw.call(ctx, h.bridgeAddr(), 30000, sip.NewHeader("X-Falcon-Leg", legPrefix("0123456789abcdef")+"-abc"))
	var dr *sipgo.ErrDialogResponse
	if !errors.As(err, &dr) || dr.Res.StatusCode != 482 {
		t.Fatalf("want 482, got %v", err)
	}
}

// A carrier chain strips X-Falcon-Leg. The loop is then the same caller
// and number while leg B rings. Falcon refuses the copy and ends its own
// leg B at once, so the switch stops trying carriers.
func TestBridgeEndsALoopWithoutTheLegHeader(t *testing.T) {
	h := newHarness(t, options{action: score.ActionAllow, carryAll: true})
	copyResult := make(chan error, 1)
	h.sw.onB = func(in *inbound) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _, err := h.sw.call(ctx, h.bridgeAddr(), 30002)
			copyResult <- err
		}()
		<-in.dlg.Context().Done()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, _, err := h.sw.call(ctx, h.bridgeAddr(), 30000)
	var dr *sipgo.ErrDialogResponse
	if !errors.As(err, &dr) || dr.Res.StatusCode != 482 {
		t.Fatalf("the first call must end with 482, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("the loop took %v to end", time.Since(start))
	}
	select {
	case err := <-copyResult:
		if !errors.As(err, &dr) || dr.Res.StatusCode != 482 {
			t.Fatalf("the copy must get 482, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the copy got no answer")
	}
}

// A crash leaves calls up on the switch. The next start hangs them up on
// both legs from what Falcon saved when the call was answered.
func TestRestartHangsUpCallsACrashLeftUp(t *testing.T) {
	h := newHarness(t, options{action: score.ActionAllow, carryAll: true})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dlgA, _, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err != nil {
		t.Fatalf("carry: %v", err)
	}
	_ = dlgA.Ack(ctx)
	legB := <-h.sw.legBs
	callA, callB := callIDOf(dlgA.InviteRequest), callIDOf(legB.req)
	waitFor(t, "saved row", 3*time.Second, func() bool {
		rows, _ := h.db.LiveCalls(context.Background())
		return len(rows) == 1 && rows[0].AOK != ""
	})

	portBase += 200
	restarted, err := New(Config{
		Listen: "127.0.0.1:0", Peers: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, MediaIP: "127.0.0.1",
		RTPPortMin: portBase, RTPPortMax: portBase + 199, MaxCalls: 20, MaxDuration: time.Hour,
		RTPTimeout: 30 * time.Second, ScreenTimeout: time.Second, PassStatus: 503, Version: "test", InstallID: "fedcba9876543210",
	}, h.screen, fakeControls{mode: "enforce", fasMode: "monitor"}, h.sink, h.db)
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { _ = restarted.Serve(rctx); close(stopped) }()
	defer func() { rcancel(); <-stopped }()

	got := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for len(got) < 2 {
		select {
		case bye := <-h.sw.byes:
			got[callIDOf(bye)] = true
		case <-deadline:
			t.Fatalf("BYE on %d legs, want both: %v", len(got), got)
		}
	}
	if !got[callA] || !got[callB] {
		t.Fatalf("BYE went to %v, want %s and %s", got, callA, callB)
	}
	waitFor(t, "row deleted", 3*time.Second, func() bool {
		rows, _ := h.db.LiveCalls(context.Background())
		return len(rows) == 0
	})
}

func TestByeFromSavedLegs(t *testing.T) {
	inviteA := "INVITE sip:+14155550100@10.0.0.9:5060 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKa\r\n" +
		"Record-Route: <sip:10.0.0.1;lr>\r\nRecord-Route: <sip:10.0.0.2;lr>\r\n" +
		"From: <sip:+13125550188@10.0.0.1>;tag=caller\r\nTo: <sip:+14155550100@10.0.0.9>\r\n" +
		"Call-ID: leg-a\r\nCSeq: 7 INVITE\r\nContact: <sip:sw@10.0.0.1:5070>\r\nContent-Length: 0\r\n\r\n"
	okA := "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKa\r\n" +
		"From: <sip:+13125550188@10.0.0.1>;tag=caller\r\nTo: <sip:+14155550100@10.0.0.9>;tag=falcon\r\n" +
		"Call-ID: leg-a\r\nCSeq: 7 INVITE\r\nContact: <sip:falcon@10.0.0.9:5060>\r\nContent-Length: 0\r\n\r\n"
	bye, err := byeFromSaved(inviteA, okA, byeAsCallee)
	if err != nil {
		t.Fatal(err)
	}
	if bye.Recipient.Host != "10.0.0.1" || bye.Recipient.Port != 5070 {
		t.Fatalf("leg A target %s", bye.Recipient.String())
	}
	if tag, _ := bye.From().Params.Get("tag"); tag != "falcon" {
		t.Fatalf("leg A From tag %q", tag)
	}
	if tag, _ := bye.To().Params.Get("tag"); tag != "caller" {
		t.Fatalf("leg A To tag %q", tag)
	}
	if r := bye.GetHeaders("Route"); len(r) != 2 || r[0].Value() != "<sip:10.0.0.1;lr>" {
		t.Fatalf("leg A routes %v", r)
	}
	if bye.CSeq().MethodName != sip.BYE || bye.CallID().Value() != "leg-a" {
		t.Fatalf("leg A %s %s", bye.CSeq().Value(), bye.CallID().Value())
	}

	inviteB := "INVITE sip:+14155550100@10.0.0.1:5060 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKb\r\n" +
		"From: <sip:+13125550188@10.0.0.9>;tag=falconb\r\nTo: <sip:+14155550100@10.0.0.1>\r\n" +
		"Call-ID: leg-b\r\nCSeq: 12 INVITE\r\nContact: <sip:falcon@10.0.0.9:5060>\r\nContent-Length: 0\r\n\r\n"
	okB := "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKb\r\n" +
		"Record-Route: <sip:10.0.0.3;lr>\r\nRecord-Route: <sip:10.0.0.4;lr>\r\n" +
		"From: <sip:+13125550188@10.0.0.9>;tag=falconb\r\nTo: <sip:+14155550100@10.0.0.1>;tag=far\r\n" +
		"Call-ID: leg-b\r\nCSeq: 12 INVITE\r\nContact: <sip:far@10.0.0.5:5080>\r\nContent-Length: 0\r\n\r\n"
	bye, err = byeFromSaved(inviteB, okB, byeAsCaller)
	if err != nil {
		t.Fatal(err)
	}
	if bye.Recipient.Host != "10.0.0.5" || bye.Recipient.Port != 5080 {
		t.Fatalf("leg B target %s", bye.Recipient.String())
	}
	if tag, _ := bye.From().Params.Get("tag"); tag != "falconb" {
		t.Fatalf("leg B From tag %q", tag)
	}
	if tag, _ := bye.To().Params.Get("tag"); tag != "far" {
		t.Fatalf("leg B To tag %q", tag)
	}
	if r := bye.GetHeaders("Route"); len(r) != 2 || r[0].Value() != "<sip:10.0.0.4;lr>" {
		t.Fatalf("leg B routes must be the 200 Record-Route reversed: %v", r)
	}
	if bye.Destination() != "10.0.0.4:5060" {
		t.Fatalf("leg B next hop %s", bye.Destination())
	}
	if bye.CSeq().SeqNo <= 12 {
		t.Fatalf("leg B CSeq %d must pass the INVITE", bye.CSeq().SeqNo)
	}
}

func TestSendsElsewhere(t *testing.T) {
	peer := netip.MustParseAddrPort("162.243.163.173:5060")
	cases := []struct {
		route *store.Route
		want  bool
	}{
		{nil, false},
		{&store.Route{Prefix: "9901"}, false},
		{&store.Route{Prefix: "7001", Target: "162.243.163.173:5080"}, false},
		{&store.Route{Prefix: "7001", Target: "52.50.165.204:5060"}, true},
		{&store.Route{Prefix: "7001", Target: "pbx.example.com:5060"}, true},
	}
	for _, c := range cases {
		if got := sendsElsewhere(c.route, peer); got != c.want {
			t.Errorf("%+v: got %v", c.route, got)
		}
	}
}

// With no customer that owns the caller, a call Falcon sends back to the
// switch is the switch's own outbound traffic.
func TestBridgeCallsBackToTheSwitchAreUsuallyOutbound(t *testing.T) {
	h := newHarness(t, options{action: score.ActionAllow})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _ = h.sw.call(ctx, h.bridgeAddr(), 30000)
	h.screen.mu.Lock()
	usual := h.screen.last.Usual
	h.screen.mu.Unlock()
	if usual != "outbound" {
		t.Fatalf("usual %q", usual)
	}
}

// The INVITE goes out as one raw datagram. A sipgo client would keep
// retransmitting, and force-cancelling its transaction races sipgo's
// retransmit timer.
func TestBridgeIgnoresAddressesOutsideThePeerList(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge, peers: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	conn, err := net.DialUDP("udp", nil, h.br.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local := conn.LocalAddr().String()
	body := string(sdpFor(30000))
	invite := "INVITE sip:+14155550100@" + h.bridgeAddr() + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + local + ";branch=z9hG4bKstranger1;rport\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:+13125550188@" + local + ">;tag=s1\r\n" +
		"To: <sip:+14155550100@" + h.bridgeAddr() + ">\r\n" +
		"Call-ID: stranger-1@" + local + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:+13125550188@" + local + ">\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	if _, err := conn.Write([]byte(invite)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 4096)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("a stranger got an answer: %q", buf[:n])
	}
	waitFor(t, "drop counted", 2*time.Second, func() bool { return h.br.Dropped() > 0 })
}

func TestVendorRouteLabelsStripsAndCarriesCleanCalls(t *testing.T) {
	h := newHarness(t, options{action: score.ActionAllow})
	if _, err := h.db.PutRoute(context.Background(), store.Route{Prefix: "+1415", Label: "Vendor X", Strip: false, Carry: store.CarryAll}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.PutRoute(context.Background(), store.Route{Prefix: "+14155", Label: "Vendor Y", Strip: true, Carry: store.CarryAll}); err != nil {
		t.Fatal(err)
	}
	if err := h.br.ReloadRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dlgA, _, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err != nil {
		t.Fatalf("a route with carry all must carry a clean call: %v", err)
	}
	_ = dlgA.Ack(ctx)
	in := <-h.sw.legBs
	if in.req.Recipient.User != "550100" {
		t.Fatalf("longest prefix not stripped: %s", in.req.Recipient.User)
	}
	_ = dlgA.Bye(ctx)
	callID := callIDOf(dlgA.InviteRequest)
	waitFor(t, "row", 5*time.Second, func() bool { return h.mediaRow(callID).EndMS > 0 })
	if row := h.mediaRow(callID); row.Route != "Vendor Y" || row.Carry != CarryRoute {
		t.Fatalf("row %+v", row)
	}
}

func TestShutdownHangsUpBothLegs(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dlgA, _, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err != nil {
		t.Fatal(err)
	}
	_ = dlgA.Ack(ctx)
	<-h.sw.legBs
	time.Sleep(200 * time.Millisecond)
	h.cancel()
	legs := map[string]bool{}
	timeout := time.After(6 * time.Second)
	for len(legs) < 2 {
		select {
		case bye := <-h.sw.byes:
			legs[callIDOf(bye)] = true
		case <-timeout:
			t.Fatalf("shutdown left a leg up: %v", legs)
		}
	}
}

// A shutdown while the far end rings answers the caller with 503 and
// cancels the far end, so no leg is left to answer into nothing.
func TestShutdownCancelsARingingFarEnd(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge})
	cancelled := make(chan struct{}, 1)
	h.sw.onB = func(in *inbound) {
		_ = in.dlg.Respond(180, "Ringing", nil)
		<-in.dlg.Context().Done()
		cancelled <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, err := h.sw.call(ctx, h.bridgeAddr(), 30000)
		result <- err
	}()
	<-h.sw.legBs
	time.Sleep(200 * time.Millisecond)
	h.cancel()
	select {
	case err := <-result:
		var dr *sipgo.ErrDialogResponse
		if !errors.As(err, &dr) || dr.Res.StatusCode != 503 {
			t.Fatalf("caller: want 503, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the caller got no final answer")
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the ringing far end was not cancelled")
	}
}

func TestReinviteRefreshKeepsTheCallUp(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dlgA, _, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err != nil {
		t.Fatal(err)
	}
	_ = dlgA.Ack(ctx)
	<-h.sw.legBs
	aPort := sdpPort(t, dlgA.InviteResponse.Body())
	re := sip.NewRequest(sip.INVITE, dlgA.InviteResponse.Contact().Address)
	re.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	re.SetBody(sdpFor(caller.port()))
	res, err := dlgA.Do(ctx, re)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("re-INVITE: %v %v", res, err)
	}
	if sdpPort(t, res.Body()) != aPort {
		t.Fatalf("re-INVITE answer moved the media: %d vs %d", sdpPort(t, res.Body()), aPort)
	}
	if h.br.Active() != 1 {
		t.Fatalf("active %d after refresh", h.br.Active())
	}
	_ = dlgA.Bye(ctx)
}

func TestFASMonitorRecordsRingbackAfterAnswer(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge, fasMode: "monitor"})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dlgA, _, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err != nil {
		t.Fatalf("monitor must answer at once: %v", err)
	}
	_ = dlgA.Ack(ctx)
	in := <-h.sw.legBs
	bPort := sdpPort(t, in.req.Body())
	audio := append(ringback(2000), speech(1500, 3)...)
	callee.send(bPort, audio, 33)
	_ = dlgA.Bye(ctx)
	callID := callIDOf(dlgA.InviteRequest)
	waitFor(t, "fas verdict", 5*time.Second, func() bool { return h.mediaRow(callID).EndMS > 0 })
	row := h.mediaRow(callID)
	if row.FAS != "ringback" || row.FASAction != "observed" || row.FASMS < 1500 || row.FASMS > 2800 {
		t.Fatalf("row %+v detail %s", row, row.FASDetail)
	}
	ev, _, _ := h.db.EventByCallID(context.Background(), callID)
	found := false
	for _, r := range ev.Reasons {
		found = found || r.Code == "fas_ringback"
	}
	if !found {
		t.Fatalf("fas reason not on the event: %+v", ev.Reasons)
	}
}

func TestFASEnforceFailsAFalseAnswerBackToTheSwitch(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge, fasMode: "enforce"})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() {
		in := <-h.sw.legBs
		callee.send(sdpPort(t, in.req.Body()), ringback(6000), 44)
	}()
	dlgA, codes, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	var dr *sipgo.ErrDialogResponse
	if !errors.As(err, &dr) || dr.Res.StatusCode != 480 {
		t.Fatalf("want 480 after a false answer, got %v (codes %v)", err, codes)
	}
	var seen []int
	for _, c := range codes {
		if c != 100 {
			seen = append(seen, c)
		}
	}
	if len(seen) == 0 || seen[0] != 183 {
		t.Fatalf("caller did not get early audio first: %v", codes)
	}
	select {
	case <-h.sw.byes:
	case <-time.After(3 * time.Second):
		t.Fatal("the false answer was left up")
	}
	callID := callIDOf(dlgA.InviteRequest)
	waitFor(t, "row", 5*time.Second, func() bool { return h.mediaRow(callID).EndMS > 0 })
	if row := h.mediaRow(callID); row.FAS != "ringback" || row.FASAction != "failed" || row.Status != 480 {
		t.Fatalf("row %+v", row)
	}
}

func TestFASEnforcePassesARealAnswerWhenThePersonSpeaks(t *testing.T) {
	h := newHarness(t, options{action: score.ActionChallenge, fasMode: "enforce"})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	started := time.Now()
	go func() {
		in := <-h.sw.legBs
		callee.send(sdpPort(t, in.req.Body()), speech(2000, 5), 55)
	}()
	dlgA, codes, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err != nil {
		t.Fatalf("a real answer was not passed: %v %v", err, codes)
	}
	if d := time.Since(started); d > 1400*time.Millisecond {
		t.Fatalf("answer held %s, past the speech", d)
	}
	_ = dlgA.Ack(ctx)
	_ = dlgA.Bye(ctx)
	callID := callIDOf(dlgA.InviteRequest)
	waitFor(t, "row", 5*time.Second, func() bool { return h.mediaRow(callID).EndMS > 0 })
	if row := h.mediaRow(callID); row.FAS != "" || row.Status != 200 {
		t.Fatalf("row %+v", row)
	}
}

// In PBX mode a clean call is carried, not passed back with 503, and the
// bridge tells the screen the direction it was set up with.
func TestBridgeCarriesEveryCallWhenCarryAllIsOn(t *testing.T) {
	h := newHarness(t, options{action: score.ActionAllow, carryAll: true, direction: "outbound"})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dlgA, codes, err := h.sw.call(ctx, h.bridgeAddr(), caller.port())
	if err != nil {
		t.Fatalf("a clean call must be carried: %v (codes %v)", err, codes)
	}
	_ = dlgA.Ack(ctx)
	select {
	case <-h.sw.legBs:
	case <-time.After(3 * time.Second):
		t.Fatal("no leg B for a clean call")
	}
	_ = dlgA.Bye(ctx)
	callID := callIDOf(dlgA.InviteRequest)
	waitFor(t, "row", 5*time.Second, func() bool { return h.mediaRow(callID).Carry == CarryEvery })
	h.screen.mu.Lock()
	dir := h.screen.last.Direction
	h.screen.mu.Unlock()
	if dir != "outbound" {
		t.Fatalf("direction %q", dir)
	}
}

// Signed INVITEs often pass 1300 bytes, and switches send them as UDP.
// The bridge must send its leg B over UDP at the same size.
func TestBridgeCarriesAnInviteLargerThanOneUDPPacket(t *testing.T) {
	h := newHarness(t, options{action: score.ActionAllow, carryAll: true})
	caller, callee := newEndpoint(t), newEndpoint(t)
	h.sw.onB = answerWith(callee.port(), true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	identity := strings.Repeat("e", 1400) + ";info=<https://cert.example/shaken.crt>;alg=ES256;ppt=shaken"
	dlgA, codes, err := h.sw.call(ctx, h.bridgeAddr(), caller.port(), sip.NewHeader("Identity", identity))
	if err != nil {
		t.Fatalf("a large INVITE must be carried: %v (codes %v)", err, codes)
	}
	_ = dlgA.Ack(ctx)
	select {
	case in := <-h.sw.legBs:
		if got := in.req.GetHeader("Identity"); got == nil || got.Value() != identity {
			t.Fatal("leg B lost the Identity header")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no leg B for a large INVITE")
	}
	_ = dlgA.Bye(ctx)
}

func TestBridgeStillRejectsHardBlocksWhenCarryAllIsOn(t *testing.T) {
	h := newHarness(t, options{action: score.ActionReject, carryAll: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := h.sw.call(ctx, h.bridgeAddr(), 30000)
	var dr *sipgo.ErrDialogResponse
	if !errors.As(err, &dr) || dr.Res.StatusCode != 603 {
		t.Fatalf("want 603, got %v", err)
	}
}

func TestCustomerOfReadsTheSwitchHeader(t *testing.T) {
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "+14155550100", Host: "127.0.0.1"})
	if got := customerOf(req); got != "" {
		t.Fatalf("no header gave %q", got)
	}
	req.AppendHeader(sip.NewHeader("X-Falcon-Customer", "  acme-wholesale "))
	if got := customerOf(req); got != "acme-wholesale" {
		t.Fatalf("customer %q", got)
	}
}

func TestDirectionOfFollowsTheSettingThenTheSwitch(t *testing.T) {
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "+14155550100", Host: "127.0.0.1"})
	auto := &Server{cfg: Config{Direction: "auto"}}
	if got := auto.directionOf(req); got != "" {
		t.Fatalf("auto with no header gave %q", got)
	}
	req.AppendHeader(sip.NewHeader("X-Falcon-Direction", "Outbound"))
	if got := auto.directionOf(req); got != "outbound" {
		t.Fatalf("header gave %q", got)
	}
	fixed := &Server{cfg: Config{Direction: "inbound"}}
	if got := fixed.directionOf(req); got != "inbound" {
		t.Fatalf("a fixed direction must win, got %q", got)
	}
}
