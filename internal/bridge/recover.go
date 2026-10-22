package bridge

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/store"
	"github.com/emiago/sipgo/sip"
)

// leftoverByeTimeout bounds one BYE to a call a previous run left up.
const leftoverByeTimeout = 5 * time.Second

// calleeCSeq is the CSeq of the BYE Falcon sends as the callee of leg A.
// Falcon's own requests in that dialog start from a small number, and this
// one only has to be higher than those.
const calleeCSeq = 1_000_000_000

// callerCSeqStep moves the BYE on leg B past any re-INVITE Falcon sent.
const callerCSeqStep = 100_000

// saveLive stores the call so that a restart can hang it up. Falcon calls
// it when the far end answers, and again when it answers the caller.
func (c *call) saveLive() {
	c.mu.Lock()
	row := c.live
	c.mu.Unlock()
	if row.BOK == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.s.calls.SaveLiveCall(ctx, row); err != nil {
		log.Printf("falcon bridge: save %s for restart cleanup: %v", c.id, err)
	}
}

// leftovers reads the calls a previous run left up. Serve reads them before
// it takes new calls.
func (s *Server) leftovers(ctx context.Context) []store.LiveCall {
	rows, err := s.calls.LiveCalls(ctx)
	if err != nil {
		log.Printf("falcon bridge: read calls left up by a previous run: %v", err)
		return nil
	}
	return rows
}

// listenWait bounds the wait for sipgo to serve the SIP socket.
const listenWait = 3 * time.Second

// hangUpLeftovers ends the calls a previous run left up. Falcon saves each
// call when its far end answers and deletes it when the call ends, so a row
// that is still here is a call a crash left billed on the switch. A row
// stays until the switch confirms every BYE, or until it is older than the
// longest call.
func (s *Server) hangUpLeftovers(ctx context.Context, rows []store.LiveCall) {
	if len(rows) == 0 {
		return
	}
	if !s.listening(ctx) {
		log.Printf("falcon bridge: SIP is not up, so %d calls left up by a previous run stay saved for the next start", len(rows))
		return
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ended, legs := 0, 0
	for _, row := range rows {
		wg.Add(1)
		go func(row store.LiveCall) {
			defer wg.Done()
			ok, sent := s.byeLeftover(ctx, row)
			if ok == sent || time.Since(row.Saved) > s.maxCallAge() {
				if err := s.calls.DeleteLiveCall(context.Background(), row.CallID); err != nil {
					log.Printf("falcon bridge: forget %s: %v", row.CallID, err)
				}
			}
			mu.Lock()
			ended, legs = ended+ok, legs+sent
			mu.Unlock()
		}(row)
	}
	wg.Wait()
	log.Printf("falcon bridge: %d calls were up when Falcon last stopped; the switch confirmed BYE on %d of %d legs", len(rows), ended, legs)
}

// listening waits until sipgo serves the SIP socket. A request sent before
// that makes sipgo bind a second socket on the same port, which fails.
func (s *Server) listening(ctx context.Context) bool {
	addr := s.udp.LocalAddr().String()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(listenWait)
	defer deadline.Stop()
	for {
		if _, err := s.ua.TransportLayer().GetConnection("udp", addr); err == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-tick.C:
		}
	}
}

// maxCallAge is how long a saved call can still be up on the switch.
func (s *Server) maxCallAge() time.Duration {
	if s.cfg.MaxDuration > 0 {
		return s.cfg.MaxDuration
	}
	return 4 * time.Hour
}

// byeLeftover sends BYE on each answered leg of one call. It returns the
// number of legs the switch confirmed and the number of BYEs sent.
func (s *Server) byeLeftover(ctx context.Context, row store.LiveCall) (int, int) {
	var byes []*sip.Request
	if row.AOK != "" {
		if bye, err := byeFromSaved(row.AInvite, row.AOK, byeAsCallee); err == nil {
			byes = append(byes, bye)
		} else {
			log.Printf("falcon bridge: leg A of %s: %v", row.CallID, err)
		}
	}
	if bye, err := byeFromSaved(row.BInvite, row.BOK, byeAsCaller); err == nil {
		byes = append(byes, bye)
	} else {
		log.Printf("falcon bridge: leg B of %s: %v", row.CallID, err)
	}
	ok := 0
	for _, bye := range byes {
		bctx, cancel := context.WithTimeout(ctx, leftoverByeTimeout)
		res, err := s.dua.Client.Do(bctx, bye)
		cancel()
		switch {
		case err != nil:
			log.Printf("falcon bridge: BYE for %s left up by a previous run: %v", callIDOf(bye), err)
		case res.StatusCode == 200 || res.StatusCode == 481:
			// 481: the switch already ended the call.
			ok++
		default:
			log.Printf("falcon bridge: BYE for %s left up by a previous run: %d", callIDOf(bye), res.StatusCode)
		}
	}
	return ok, len(byes)
}

func byeFromSaved(rawInvite, rawOK string, build func(*sip.Request, *sip.Response) (*sip.Request, error)) (*sip.Request, error) {
	m, err := sip.ParseMessage([]byte(rawInvite))
	if err != nil {
		return nil, fmt.Errorf("saved INVITE: %w", err)
	}
	invite, ok := m.(*sip.Request)
	if !ok {
		return nil, errors.New("saved INVITE is not a request")
	}
	m, err = sip.ParseMessage([]byte(rawOK))
	if err != nil {
		return nil, fmt.Errorf("saved 200: %w", err)
	}
	res, ok := m.(*sip.Response)
	if !ok {
		return nil, errors.New("saved 200 is not a response")
	}
	return build(invite, res)
}

// byeAsCallee is the BYE Falcon sends on leg A, where the switch called
// Falcon. RFC 3261 12.1.1: the remote target is the INVITE Contact and the
// route set is the INVITE Record-Route in order. From and To swap.
func byeAsCallee(invite *sip.Request, ok *sip.Response) (*sip.Request, error) {
	contact := invite.Contact()
	from, to := ok.To(), invite.From()
	if contact == nil || from == nil || to == nil || invite.CallID() == nil {
		return nil, errors.New("saved leg A is incomplete")
	}
	bye := sip.NewRequest(sip.BYE, *contact.Address.Clone())
	routes := invite.GetHeaders("Record-Route")
	for _, h := range routes {
		bye.AppendHeader(sip.NewHeader("Route", h.Value()))
	}
	bye.AppendHeader(&sip.FromHeader{DisplayName: from.DisplayName, Address: *from.Address.Clone(), Params: from.Params.Clone()})
	bye.AppendHeader(&sip.ToHeader{DisplayName: to.DisplayName, Address: *to.Address.Clone(), Params: to.Params.Clone()})
	bye.AppendHeader(sip.HeaderClone(invite.CallID()))
	bye.AppendHeader(&sip.CSeqHeader{SeqNo: calleeCSeq, MethodName: sip.BYE})
	bye.SetTransport(invite.Transport())
	if len(routes) > 0 {
		setNextHop(bye, routes[0].Value())
	}
	return bye, nil
}

// byeAsCaller is the BYE Falcon sends on leg B, where Falcon called the
// switch. RFC 3261 12.1.2: the remote target is the 200 Contact and the
// route set is the 200 Record-Route in reverse.
func byeAsCaller(invite *sip.Request, ok *sip.Response) (*sip.Request, error) {
	from, to, cseq := invite.From(), ok.To(), invite.CSeq()
	if from == nil || to == nil || cseq == nil || invite.CallID() == nil {
		return nil, errors.New("saved leg B is incomplete")
	}
	target := invite.Recipient
	if c := ok.Contact(); c != nil {
		target = c.Address
	}
	bye := sip.NewRequest(sip.BYE, *target.Clone())
	routes := ok.GetHeaders("Record-Route")
	for i := len(routes) - 1; i >= 0; i-- {
		bye.AppendHeader(sip.NewHeader("Route", routes[i].Value()))
	}
	bye.AppendHeader(&sip.FromHeader{DisplayName: from.DisplayName, Address: *from.Address.Clone(), Params: from.Params.Clone()})
	bye.AppendHeader(&sip.ToHeader{DisplayName: to.DisplayName, Address: *to.Address.Clone(), Params: to.Params.Clone()})
	bye.AppendHeader(sip.HeaderClone(invite.CallID()))
	bye.AppendHeader(&sip.CSeqHeader{SeqNo: cseq.SeqNo + callerCSeqStep, MethodName: sip.BYE})
	bye.SetTransport(invite.Transport())
	if len(routes) > 0 {
		setNextHop(bye, routes[len(routes)-1].Value())
	}
	return bye, nil
}

// setNextHop sends a request with a route set to its first route.
func setNextHop(req *sip.Request, route string) {
	var u sip.Uri
	addr := route
	if i, j := strings.IndexByte(addr, '<'), strings.IndexByte(addr, '>'); i >= 0 && j > i {
		addr = addr[i+1 : j]
	}
	if err := sip.ParseUri(addr, &u); err != nil || u.Host == "" {
		return
	}
	port := u.Port
	if port == 0 {
		port = 5060
	}
	req.SetDestination(u.Host + ":" + strconv.Itoa(port))
}
