package bridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/fas"
	"github.com/callerapi/falcon/internal/httpapi"
	"github.com/callerapi/falcon/internal/media"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// Who ended a call.
const (
	endCaller   = "caller"
	endCallee   = "callee"
	endTimeout  = "timeout"
	endLimit    = "limit"
	endShutdown = "shutdown"
	endFalcon   = "falcon"
	endFailed   = "failed"
)

// ringTimeout ends a call the far end never answers. Switches give up
// sooner. This only bounds a lost CANCEL.
const ringTimeout = 3 * time.Minute

// headersToB are carried from the INVITE to the outbound leg. Supported,
// Require, and the session timer headers are not: Falcon does not do
// reliable provisionals or timers on the bridge.
var headersToB = []string{
	"P-Asserted-Identity", "P-Preferred-Identity", "Remote-Party-ID", "Privacy", "Identity",
	"Diversion", "History-Info", "P-Charge-Info", "Accept-Language",
}

func (s *Server) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	if to := req.To(); to != nil && to.Params != nil && to.Params.Has("tag") {
		s.onReinvite(req, tx)
		return
	}
	peer, ok := s.admit(req)
	if !ok {
		return
	}
	route := s.routes.match(req.Recipient.User)
	backToSwitch := !sendsElsewhere(route, peer)
	if backToSwitch {
		if looped, owner := s.loopOf(req); looped {
			respond(req, tx, 482, "Loop Detected", nil)
			if owner != nil {
				owner.abortLoop()
			}
			return
		}
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
	received := time.Now()
	base := s.base()
	usual := ""
	if backToSwitch {
		usual = config.DirectionOutbound
	}
	called := req.Recipient.User
	if route != nil && route.Strip {
		called = strings.TrimPrefix(called, route.Prefix)
	}
	sctx, cancel := context.WithTimeout(base, s.cfg.ScreenTimeout)
	res, err := s.screen.Screen(sctx, httpapi.ScreenRequest{
		RawSIP: req.String(), SourceIP: sourceIP(req, peer), SourcePort: int(peer.Port()),
		Switch: "sip/" + peer.Addr().Unmap().String(), Received: received,
		Direction: s.directionOf(req), Customer: customerOf(req), Usual: usual, Called: called,
	})
	cancel()
	if err != nil {
		res = score.Result{Action: score.ActionAllow, Headers: map[string]string{"X-Falcon-Action": "allow", "X-Falcon-Error": err.Error()}}
	}
	fanoutEvery, cleanEvery := s.ctl.Sampling(base)
	d := s.policy.Decide(res, Rules{Mode: s.ctl.Mode(base), FanoutEvery: fanoutEvery, CleanEvery: cleanEvery, CarryAll: s.ctl.CarryAll(base)}, route)
	switch d.Plan {
	case Reject:
		status, reason := res.SIPStatus, res.SIPReason
		if status < 400 || status == 407 {
			status, reason = 603, "Decline"
		}
		respond(req, tx, status, firstNonEmpty(reason, reasonPhrase(status)), res.Headers)
		return
	case Pass:
		respond(req, tx, s.cfg.PassStatus, reasonPhrase(s.cfg.PassStatus), res.Headers)
		return
	}
	if s.Active() >= s.Capacity() {
		res.Headers["X-Falcon-Bridge"] = "full"
		respond(req, tx, s.cfg.PassStatus, reasonPhrase(s.cfg.PassStatus), res.Headers)
		return
	}
	offer, err := media.ParseSDP(req.Body())
	if err != nil {
		// No early offer: the bridge does not carry delayed-offer calls.
		res.Headers["X-Falcon-Bridge"] = "no-sdp"
		respond(req, tx, s.cfg.PassStatus, reasonPhrase(s.cfg.PassStatus), res.Headers)
		return
	}
	c := &call{
		s: s, id: callIDOf(req), peer: peer, host: s.mediaHost(peer.Addr()), started: received,
		route: route, reason: d.Reason, aReq: req, aTx: tx, aOffer: offer, done: make(chan struct{}),
	}
	if !s.track(&s.setups) {
		res.Headers["X-Falcon-Bridge"] = "stopping"
		respond(req, tx, s.cfg.PassStatus, reasonPhrase(s.cfg.PassStatus), res.Headers)
		return
	}
	defer s.setups.Done()
	c.run()
}

func (s *Server) base() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// call is one bridged call: leg A from the switch, leg B back out.
type call struct {
	s       *Server
	id      string
	peer    netip.AddrPort
	host    string
	started time.Time
	route   *store.Route
	reason  string

	aReq   *sip.Request
	aTx    sip.ServerTransaction
	aOffer *media.SDP
	a      *sipgo.DialogServerSession
	b      *sipgo.DialogClientSession
	bID    string
	loop   string

	sockA, sockB *media.Socket
	relay        *media.Relay
	rec          *media.Recorder
	det          *fas.Detector
	row          store.MediaCall

	mu         sync.Mutex
	aSDP       []byte
	bSDP       []byte
	codec      string
	decodable  bool
	earlySent  bool
	finalSent  bool
	connected  bool
	answered   bool
	ringAt     time.Time
	answerAt   time.Time
	connectAt  time.Time
	endAt      time.Time
	status     int
	endedBy    string
	fasAction  string
	looped     bool
	live       store.LiveCall
	stopRing   context.CancelFunc
	torn       sync.Once
	done       chan struct{}
	finalizing sync.WaitGroup
}

// dialogInvite is the INVITE the dialog owns. sipgo 1.6 clones it and
// puts the To tag on the clone. A response built from the original
// request gets a different tag, and the dialog then rejects the 200.
func (c *call) dialogInvite() *sip.Request {
	if c.a != nil && c.a.InviteRequest != nil {
		return c.a.InviteRequest
	}
	return c.aReq
}

func (c *call) contact() sip.Header {
	_, port := c.s.viaAddr()
	return &sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: "falcon", Host: c.host, Port: port}}
}

// run sets the call up. It returns once leg A has a final answer.
func (c *call) run() {
	s := c.s
	a, err := s.dua.ReadInvite(c.aReq, c.aTx)
	if err != nil {
		respond(c.aReq, c.aTx, s.cfg.PassStatus, reasonPhrase(s.cfg.PassStatus), map[string]string{"X-Falcon-Bridge": "no-contact"})
		return
	}
	c.a = a
	if c.sockA, err = s.ports.Allocate(); err == nil {
		c.sockB, err = s.ports.Allocate()
	}
	if err != nil {
		s.ports.Release(c.sockA)
		c.finalA(s.cfg.PassStatus, map[string]string{"X-Falcon-Bridge": "no-ports"})
		return
	}
	if !s.track(&s.wg) {
		s.ports.Release(c.sockA)
		s.ports.Release(c.sockB)
		c.finalA(s.cfg.PassStatus, map[string]string{"X-Falcon-Bridge": "stopping"})
		return
	}
	s.active.Add(1)
	c.det = fas.NewDetector(c.started)
	taps := media.Taps{fasTap{c.det}}
	if s.cfg.RecordingsDir != "" {
		if rec, err := media.NewRecorder(s.cfg.RecordingsDir, media.RecordingName(c.started, c.id), c.started, s.cfg.RecordMax); err == nil {
			c.rec = rec
			taps = append(taps, rec)
		} else {
			log.Printf("falcon bridge: recording off for %s: %v", c.id, err)
		}
	}
	c.relay = media.NewRelay(c.sockA, c.sockB, taps)
	c.relay.SetCodecs(media.SideA, c.aOffer.Codecs)
	_ = c.relay.SetRemote(media.SideA, c.aOffer.Addr, c.aOffer.Port)
	c.relay.Start()
	s.register(c, c.id)

	c.row = store.MediaCall{CallID: c.id, Carry: c.reason, StartedAt: c.started}
	if c.route != nil {
		c.row.Route = c.route.Label
	}
	if f := c.aReq.From(); f != nil {
		c.row.From = f.Address.User
	}
	c.row.To = c.aReq.Recipient.User

	bReq, err := c.buildB()
	if err != nil {
		c.status = 483
		c.finalA(483, nil)
		c.teardown(endFailed)
		return
	}
	if id, err := s.calls.InsertMediaCall(s.base(), c.row); err == nil {
		c.row.ID = id
	}
	wait, stopWait := context.WithTimeout(context.Background(), ringTimeout)
	c.mu.Lock()
	c.stopRing = stopWait
	c.mu.Unlock()
	key := loopKey(c.row.From, bReq.Recipient.User)
	s.markPending(key, c)
	b, err := s.dua.WriteInvite(s.base(), bReq)
	if err != nil {
		stopWait()
		s.clearPending(key)
		log.Printf("falcon bridge: outbound leg for %s: %v", c.id, err)
		c.status = s.cfg.PassStatus
		c.finalA(s.cfg.PassStatus, map[string]string{"X-Falcon-Bridge": "outbound-failed"})
		c.teardown(endFailed)
		return
	}
	c.b = b
	c.bID = callIDOf(bReq)
	c.row.LegBCallID = c.bID
	s.register(c, c.bID)

	callerGone := make(chan struct{})
	go func() {
		select {
		case <-a.Context().Done():
			if !c.isAnswered() {
				close(callerGone)
				stopWait()
			}
		case <-wait.Done():
		}
	}()
	err = b.WaitAnswer(wait, sipgo.AnswerOptions{OnResponse: c.onResponse})
	s.clearPending(key)
	select {
	case <-callerGone:
		// The caller cancelled. The transaction layer answered 487. A far
		// end that answered at the same moment is hung up, not left up.
		stopWait()
		if err == nil {
			c.mu.Lock()
			c.answered, c.answerAt = true, time.Now()
			c.mu.Unlock()
			_ = b.Ack(s.base())
			c.hangupB()
		}
		c.status = 487
		c.teardown(endCaller)
		return
	case <-c.done:
		// Falcon ended the call while the far end rang: a shutdown or a
		// limit. Teardown cancelled the outbound leg. A far end that
		// answered at the same moment is hung up, not left up.
		if err == nil {
			c.mu.Lock()
			c.answered, c.answerAt = true, time.Now()
			c.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = b.Ack(ctx)
			cancel()
			c.hangupB()
		}
		return
	default:
	}
	stopWait()
	if err != nil {
		var dr *sipgo.ErrDialogResponse
		status := s.cfg.PassStatus
		if c.isLooped() {
			status = 482
		} else if errors.As(err, &dr) {
			status = mapFailure(dr.Res.StatusCode, s.cfg.PassStatus)
			if dr.Res.StatusCode == 401 || dr.Res.StatusCode == 403 || dr.Res.StatusCode == 407 {
				log.Printf("falcon bridge: the switch refused Falcon's outbound leg with %d. Add %s as a customer with IP authentication.", dr.Res.StatusCode, c.host)
			}
		}
		c.status = status
		c.finalA(status, nil)
		c.teardown(endFailed)
		return
	}
	now := time.Now()
	c.mu.Lock()
	c.answered, c.answerAt = true, now
	c.live = store.LiveCall{CallID: c.id, AInvite: c.aReq.String(), BInvite: bReq.String(), BOK: b.InviteResponse.String(), Saved: now}
	c.mu.Unlock()
	c.saveLive()
	c.det.Answer(now)
	if body := b.InviteResponse.Body(); len(body) > 0 {
		if err := c.applyAnswer(body); err != nil {
			log.Printf("falcon bridge: answer SDP for %s: %v", c.id, err)
		}
	}
	if err := b.Ack(s.base()); err != nil {
		log.Printf("falcon bridge: ACK for %s: %v", c.id, err)
	}
	if s.ctl.FASMode(s.base()) == config.FASEnforce && c.decodable {
		c.hold()
		return
	}
	c.connect()
}

// buildB writes the INVITE back to the switch, or to a route's target,
// with Falcon's media address in the SDP.
func (c *call) buildB() (*sip.Request, error) {
	maxFwd := 70
	if mf := c.aReq.MaxForwards(); mf != nil {
		maxFwd = int(*mf) - 1
	}
	if maxFwd < 1 {
		return nil, errors.New("too many hops")
	}
	user := c.aReq.Recipient.User
	host, port := c.peer.Addr().Unmap().String(), 5060
	if via := c.aReq.Via(); via != nil && via.Port > 0 {
		port = via.Port
	}
	if c.route != nil {
		if c.route.Strip {
			user = strings.TrimPrefix(user, c.route.Prefix)
		}
		if t := strings.TrimSpace(c.route.Target); t != "" {
			if h, p, err := net.SplitHostPort(t); err == nil {
				host = h
				port, _ = strconv.Atoi(p)
			}
		}
	}
	recipient := sip.Uri{Scheme: "sip", User: user, Host: host, Port: port}
	req := sip.NewRequest(sip.INVITE, recipient)
	from := sip.FromHeader{Address: sip.Uri{Scheme: "sip", User: c.row.From, Host: c.host}, Params: sip.NewParams()}
	if f := c.aReq.From(); f != nil {
		from.DisplayName = f.DisplayName
		from.Address = *f.Address.Clone()
	}
	from.Params.Add("tag", sip.GenerateTagN(16))
	req.AppendHeader(&from)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: user, Host: host, Port: port}, Params: sip.NewParams()})
	mf := sip.MaxForwardsHeader(maxFwd)
	req.AppendHeader(&mf)
	req.AppendHeader(c.contact())
	for _, name := range headersToB {
		for _, h := range c.aReq.GetHeaders(name) {
			req.AppendHeader(sip.NewHeader(name, h.Value()))
		}
	}
	for _, h := range c.aReq.Headers() {
		name := h.Name()
		if strings.HasPrefix(strings.ToLower(name), "x-") && !strings.HasPrefix(strings.ToLower(name), "x-falcon-") {
			req.AppendHeader(sip.NewHeader(name, h.Value()))
		}
	}
	c.loop = legPrefix(c.s.cfg.InstallID) + "-" + randomHex(6)
	req.AppendHeader(sip.NewHeader("X-Falcon-Leg", c.loop))
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	c.mu.Lock()
	c.bSDP = c.aOffer.Rewrite(c.host, c.sockB.Port, true)
	body := c.bSDP
	c.mu.Unlock()
	req.SetBody(body)
	req.SetTransport(c.aReq.Transport())
	return req, nil
}

// onResponse passes ringing and early audio to the caller.
func (c *call) onResponse(res *sip.Response) error {
	if !res.IsProvisional() || res.StatusCode == 100 {
		return nil
	}
	c.mu.Lock()
	if c.ringAt.IsZero() {
		c.ringAt = time.Now()
	}
	c.mu.Unlock()
	if body := res.Body(); len(body) > 0 && c.applyAnswer(body) == nil {
		c.provisional(res.StatusCode, res.Reason, true)
		return nil
	}
	c.provisional(res.StatusCode, res.Reason, false)
	return nil
}

func (c *call) provisional(code int, reason string, withSDP bool) {
	c.mu.Lock()
	if c.finalSent {
		c.mu.Unlock()
		return
	}
	var body []byte
	if withSDP || c.earlySent {
		body = c.aSDP
		c.earlySent = c.earlySent || body != nil
	}
	c.mu.Unlock()
	headers := []sip.Header{c.contact()}
	if body != nil {
		headers = append(headers, sip.NewHeader("Content-Type", "application/sdp"))
	}
	if err := c.a.Respond(code, firstNonEmpty(reason, "Session Progress"), body, headers...); err != nil {
		log.Printf("falcon bridge: %d to caller for %s: %v", code, c.id, err)
	}
}

// applyAnswer points the relay at the far end and builds the SDP the
// caller gets.
func (c *call) applyAnswer(body []byte) error {
	ans, err := media.ParseSDP(body)
	if err != nil {
		return err
	}
	if err := c.relay.SetRemote(media.SideB, ans.Addr, ans.Port); err != nil {
		return err
	}
	c.relay.SetCodecs(media.SideB, ans.Codecs)
	_, name := ans.Codec()
	c.mu.Lock()
	c.aSDP = ans.Rewrite(c.host, c.sockA.Port, false)
	c.codec = name
	c.decodable = !ans.Encrypted() && media.DecoderFor(name) != nil
	c.mu.Unlock()
	return nil
}

// connect answers the caller with Falcon's SDP. It returns after the ACK.
func (c *call) connect() {
	c.mu.Lock()
	if c.finalSent {
		c.mu.Unlock()
		return
	}
	c.finalSent, c.connected, c.connectAt, c.status = true, true, time.Now(), 200
	body := c.aSDP
	c.mu.Unlock()
	res := sip.NewResponseFromRequest(c.dialogInvite(), 200, "OK", body)
	res.AppendHeader(c.contact())
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	res.AppendHeader(sip.NewHeader("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS, UPDATE, INFO"))
	c.mu.Lock()
	c.live.AOK = res.String()
	c.mu.Unlock()
	c.saveLive()
	go c.watch()
	if err := c.a.WriteResponse(res); err != nil {
		log.Printf("falcon bridge: caller did not confirm %s: %v", c.id, err)
		c.hangup(endFalcon)
	}
}

// hold keeps the caller on early audio until a person speaks. A false
// answer is never passed on: ringing or busy after the answer fails the
// call back to the switch, which routes it again.
func (c *call) hold() {
	c.mu.Lock()
	c.fasAction = "held"
	early := c.earlySent
	c.mu.Unlock()
	if !early {
		c.provisional(183, "Session Progress", true)
	}
	timer := time.NewTimer(c.s.cfg.FASHold)
	defer timer.Stop()
	heard := false
	for {
		select {
		case sig := <-c.det.Signals():
			switch sig {
			case fas.SpeechStarted:
				c.connect()
				return
			case fas.ToneHeard:
				heard = true
				timer.Reset(c.s.cfg.FASMaxRingback)
			case fas.SITHeard:
				c.failAnswered(480)
				return
			}
		case <-timer.C:
			if heard {
				c.failAnswered(480)
				return
			}
			c.connect()
			return
		case <-c.a.Context().Done():
			c.hangupB()
			c.status = 487
			c.teardown(endCaller)
			return
		case <-c.b.Context().Done():
			c.finalA(480, nil)
			c.teardown(endCallee)
			return
		case <-c.done:
			return
		}
	}
}

// failAnswered drops a far end that answered falsely and tells the switch
// the call failed, so the caller is not billed and the switch reroutes.
func (c *call) failAnswered(status int) {
	c.mu.Lock()
	c.fasAction = "failed"
	c.mu.Unlock()
	c.hangupB()
	c.finalA(status, map[string]string{"X-Falcon-FAS": "failed"})
	c.teardown(endFalcon)
}

// finalA sends one final failure to an unanswered caller. It writes before
// it returns: sipgo ends an INVITE transaction that has no final response
// when the INVITE handler returns, and the response would be lost.
func (c *call) finalA(status int, headers map[string]string) {
	c.mu.Lock()
	if c.finalSent {
		c.mu.Unlock()
		return
	}
	c.finalSent, c.status = true, status
	c.mu.Unlock()
	res := sip.NewResponseFromRequest(c.dialogInvite(), status, reasonPhrase(status), nil)
	for k, v := range headers {
		res.AppendHeader(sip.NewHeader(k, v))
	}
	if err := c.aTx.Respond(res); err != nil {
		log.Printf("falcon bridge: %d to caller for %s: %v", status, c.id, err)
	}
}

// abortLoop ends a leg B that came back to Falcon. The switch would
// otherwise try each of its carriers, and each one comes back.
func (c *call) abortLoop() {
	c.mu.Lock()
	c.looped = true
	stop := c.stopRing
	c.mu.Unlock()
	if stop != nil {
		stop()
	}
}

func (c *call) isLooped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.looped
}

func (c *call) isAnswered() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.answered
}

// watch ends a connected call whose audio stopped or that ran too long.
func (c *call) watch() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			c.mu.Lock()
			since := c.connectAt
			c.mu.Unlock()
			if last := c.relay.LastPacket(); last.After(since) {
				since = last
			}
			if c.s.cfg.RTPTimeout > 0 && time.Since(since) > c.s.cfg.RTPTimeout {
				c.hangup(endTimeout)
				return
			}
			if c.s.cfg.MaxDuration > 0 && time.Since(c.started) > c.s.cfg.MaxDuration {
				c.hangup(endLimit)
				return
			}
		}
	}
}

func (c *call) ack(req *sip.Request, tx sip.ServerTransaction) {
	if callIDOf(req) == c.id && c.a != nil {
		_ = c.a.ReadAck(req, tx)
	}
}

// bye ends the other leg the moment one leg hangs up. Leaving the far
// end up after the caller hangs up is the false answer the bridge exists
// to prevent.
func (c *call) bye(req *sip.Request, tx sip.ServerTransaction) {
	switch callIDOf(req) {
	case c.id:
		if err := c.a.ReadBye(req, tx); err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
			return
		}
		c.hangupB()
		c.teardown(endCaller)
	case c.bID:
		if err := c.b.ReadBye(req, tx); err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
			return
		}
		c.mu.Lock()
		connected := c.connected
		c.mu.Unlock()
		if connected {
			c.hangupA()
		} else {
			c.finalA(480, nil)
		}
		c.teardown(endCallee)
	}
}

// hangup ends both legs: timeout, length limit, shutdown, or a failed ACK.
func (c *call) hangup(why string) {
	c.mu.Lock()
	connected := c.connected
	c.mu.Unlock()
	c.hangupB()
	if connected {
		c.hangupA()
	} else {
		c.finalA(503, nil)
	}
	c.teardown(why)
}

func (c *call) hangupA() {
	if c.a == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.a.Bye(ctx)
}

func (c *call) hangupB() {
	if c.b == nil || !c.isAnswered() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.b.Bye(ctx)
}

// teardown releases the call once: audio, ports, the FAS verdict, the
// stored row, the call outcome, and the recording.
func (c *call) teardown(why string) {
	c.torn.Do(func() {
		c.mu.Lock()
		c.endAt = time.Now()
		if c.endedBy == "" {
			c.endedBy = why
		}
		stopRing := c.stopRing
		c.mu.Unlock()
		close(c.done)
		// A far end that still rings gets a CANCEL.
		if stopRing != nil {
			stopRing()
		}
		if c.relay != nil {
			c.relay.Close()
		}
		c.s.ports.Release(c.sockA)
		c.s.ports.Release(c.sockB)
		c.s.unregister(c.id, c.bID)
		c.s.active.Add(-1)
		go c.finish()
	})
}

func (c *call) finish() {
	defer c.s.wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c.mu.Lock()
	row := c.row
	ms := func(t time.Time) int {
		if t.IsZero() {
			return 0
		}
		return int(t.Sub(c.started) / time.Millisecond)
	}
	row.RingMS, row.AnswerMS, row.ConnectMS, row.EndMS = ms(c.ringAt), ms(c.answerAt), ms(c.connectAt), ms(c.endAt)
	row.EndedBy, row.Status, row.Codec, row.FASAction = c.endedBy, c.status, c.codec, c.fasAction
	answered, decodable, connected := c.answered, c.decodable, c.connected
	connectAt, endAt := c.connectAt, c.endAt
	saved := c.live.BOK != ""
	c.mu.Unlock()
	if saved {
		if err := c.s.calls.DeleteLiveCall(ctx, c.id); err != nil {
			log.Printf("falcon bridge: forget ended call %s: %v", c.id, err)
		}
	}
	if c.relay != nil {
		row.PacketsA, row.PacketsB = c.relay.Packets(media.SideA), c.relay.Packets(media.SideB)
	}
	var verdict fas.Verdict
	if answered && decodable {
		verdict = c.det.Verdict(endAt)
		if verdict.Kind != fas.Clean {
			row.FAS, row.FASMS = string(verdict.Kind), verdict.FalseMS
			if row.FASAction == "" {
				row.FASAction = "observed"
			}
		} else if row.FASAction == "held" {
			row.FASAction = ""
		}
		if b, err := json.Marshal(verdict.Detail); err == nil {
			row.FASDetail = b
		}
	}
	if c.rec != nil {
		if rel, secs, err := c.rec.Finish(); err == nil {
			row.Recording, row.Seconds = rel, secs
		} else if !errors.Is(err, media.ErrEmpty) {
			log.Printf("falcon bridge: recording for %s: %v", c.id, err)
		}
	}
	ev, found, _ := c.s.calls.EventByCallID(ctx, c.id)
	if found {
		row.EventID = ev.ID
	}
	if row.ID != 0 {
		if err := c.s.calls.UpdateMediaCall(ctx, row); err != nil {
			log.Printf("falcon bridge: store %s: %v", c.id, err)
		}
	}
	if found && verdict.Kind != fas.Clean {
		_ = c.s.calls.NoteReason(ctx, ev.ID, score.Reason{Code: "fas_" + string(verdict.Kind), Detail: fasDetail(verdict, row.FASAction), Category: "fas"})
	}
	if found {
		dur := 0
		if connected {
			dur = int(endAt.Sub(connectAt).Seconds())
		}
		_, _ = c.s.calls.SetOutcome(ctx, c.id, store.Outcome{Answered: connected, DurationS: dur, HangupCause: "bridge_" + row.EndedBy})
	}
	if row.Recording != "" && c.s.sink != nil {
		c.s.sink.IngestRecording(ctx, media.Recording{CallID: c.id, MediaCallID: row.ID, From: row.From, To: row.To, Path: row.Recording, Seconds: row.Seconds})
	}
}

func fasDetail(v fas.Verdict, action string) string {
	secs := float64(v.FalseMS) / 1000
	var what string
	switch v.Kind {
	case fas.Ringback:
		what = fmt.Sprintf("Ringback for %.1f s after the answer", secs)
	case fas.Busy:
		what = "Busy tone after the answer"
	case fas.SIT:
		what = "Intercept tones after the answer"
	case fas.DeadAir:
		what = fmt.Sprintf("No audio for %.1f s after the answer", secs)
	}
	switch action {
	case "held":
		return what + ". Falcon held the answer until a person spoke."
	case "failed":
		return what + ". Falcon failed the call back to the switch."
	}
	return fmt.Sprintf("%s. %.1f s were billed falsely.", what, secs)
}

// mapFailure turns the outbound leg's failure into the answer the switch
// gets for the original call. An answer that means Falcon is set up wrong
// becomes the pass status, so the switch still moves to its next vendor.
func mapFailure(status, pass int) int {
	switch {
	case status == 401 || status == 403 || status == 407 || status == 482 || status == 483:
		return pass
	case status >= 300 && status < 400:
		return pass
	case status >= 400:
		return status
	}
	return pass
}

// fasTap feeds the callee's audio to the FAS detector.
type fasTap struct{ det *fas.Detector }

func (t fasTap) Audio(side media.Side, _, _ uint32, pcm []int16, at time.Time) {
	if side == media.SideB {
		t.det.Feed(pcm, at)
	}
}

// directionOf is the fixed direction, or what the switch says in
// X-Falcon-Direction. Empty leaves it to the screen.
func (s *Server) directionOf(req *sip.Request) string {
	switch s.cfg.Direction {
	case config.DirectionInbound, config.DirectionOutbound:
		return s.cfg.Direction
	}
	if h := req.GetHeader("X-Falcon-Direction"); h != nil {
		switch v := strings.ToLower(strings.TrimSpace(h.Value())); v {
		case config.DirectionInbound, config.DirectionOutbound:
			return v
		}
	}
	return ""
}

// customerOf is the account the switch names in X-Falcon-Customer, for the
// outbound checks. Most switches can add a header to a carrier route.
func customerOf(req *sip.Request) string {
	h := req.GetHeader("X-Falcon-Customer")
	if h == nil {
		return ""
	}
	v := strings.TrimSpace(h.Value())
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}

// sourceIP is the address the switch reports: X-Source-IP, else the hop
// below the switch in Via, else the switch itself.
func sourceIP(req *sip.Request, peer netip.AddrPort) string {
	if h := req.GetHeader("X-Source-IP"); h != nil && strings.TrimSpace(h.Value()) != "" {
		return hostOnly(h.Value())
	}
	vias := req.GetHeaders("Via")
	if len(vias) >= 2 {
		if v, ok := vias[1].(*sip.ViaHeader); ok {
			if r, ok := v.Params.Get("received"); ok && r != "" {
				return r
			}
			if v.Host != "" {
				return v.Host
			}
		}
	}
	return peer.Addr().Unmap().String()
}

func hostOnly(v string) string {
	v = strings.TrimSpace(v)
	if h, _, err := net.SplitHostPort(v); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(v, "[]")
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// onReinvite answers a session refresh or a hold on either leg with that
// leg's current SDP. The far end may move its media. The bridge keeps
// relaying and does not renegotiate the other leg.
func (s *Server) onReinvite(req *sip.Request, tx sip.ServerTransaction) {
	c := s.lookup(callIDOf(req))
	if c == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
		return
	}
	c.refresh(req, tx)
}

func (c *call) refresh(req *sip.Request, tx sip.ServerTransaction) {
	side, sdp := media.SideA, c.currentSDP(media.SideA)
	if callIDOf(req) == c.bID {
		side, sdp = media.SideB, c.currentSDP(media.SideB)
		if c.b != nil {
			_ = c.b.ReadRequest(req, tx)
		}
	} else if c.a != nil {
		_ = c.a.ReadRequest(req, tx)
	}
	if body := req.Body(); len(body) > 0 {
		if offer, err := media.ParseSDP(body); err == nil && offer.Port > 0 {
			_ = c.relay.SetRemote(side, offer.Addr, offer.Port)
		}
	}
	withSDP := req.Method == sip.INVITE || (len(req.Body()) > 0 && req.Method == sip.UPDATE)
	var res *sip.Response
	if withSDP && len(sdp) > 0 {
		res = sip.NewResponseFromRequest(req, 200, "OK", sdp)
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	} else {
		res = sip.NewResponseFromRequest(req, 200, "OK", nil)
	}
	res.AppendHeader(c.contact())
	_ = tx.Respond(res)
}

func (c *call) currentSDP(side media.Side) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if side == media.SideB {
		return c.bSDP
	}
	return c.aSDP
}
