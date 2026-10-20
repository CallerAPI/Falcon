package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/fingerprint"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/shaken"
	"github.com/callerapi/falcon/internal/sipmsg"
	"github.com/callerapi/falcon/internal/store"
)

// ScreenRequest is one SIP request to score. Every transport builds one:
// the HTTP API from JSON or a raw body, the SIP listener from the wire.
type ScreenRequest struct {
	RawSIP     string `json:"raw_sip"`
	SourceIP   string `json:"source_ip"`
	SourcePort int    `json:"source_port"`
	Switch     string `json:"switch"`
	// Direction is "outbound" when the operator's own customer is
	// calling out; Customer names that account. Both optional.
	Direction  string            `json:"direction"`
	Customer   string            `json:"customer"`
	Method     string            `json:"method"`
	RequestURI string            `json:"request_uri"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	// Signing is what the switch adds when it signs the call on the way
	// out, after the screen. Ignored when the INVITE has an Identity header.
	Signing *Signing `json:"signing,omitempty"`
	// Received is when the INVITE reached Falcon. The SIP listener sets it
	// so the latency it reports includes its own parsing. Zero is now.
	Received time.Time `json:"-"`
}

// Signing is the attestation a switch applies and the certificate it
// signs with.
type Signing struct {
	Attest string `json:"attest"`
	OrigID string `json:"origid"`
	X5U    string `json:"x5u"`
}

// ErrParse means the request was not a SIP message Falcon can read. The
// caller fails open.
var ErrParse = errors.New("parse sip")

func (s *Server) handleScreen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	started := time.Now()
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil {
		s.failOpen(w, "read body")
		return
	}
	if int64(len(raw)) > MaxBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "SIP message too large"})
		return
	}

	var req ScreenRequest
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") || looksJSON(raw) {
		if err := json.Unmarshal(raw, &req); err != nil {
			s.failOpen(w, "invalid json")
			return
		}
	} else {
		req.RawSIP = string(raw)
		req.SourceIP = r.Header.Get("X-Source-IP")
		req.Switch = r.Header.Get("X-Switch")
		req.Direction = r.Header.Get("X-Direction")
		req.Customer = r.Header.Get("X-Customer")
	}
	if req.SourceIP == "" {
		req.SourceIP = headerOr(r, "X-Source-IP", clientIP(r))
	}
	req.Received = started

	result, err := s.Screen(r.Context(), req)
	if err != nil {
		s.failOpen(w, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Screen scores one request, records the event, and fans out alerts and
// the live stream. The HTTP API and the SIP listener both end here. In
// monitor mode the result tells the switch to continue and the real
// decision is in X-Falcon-Monitor.
func (s *Server) Screen(ctx context.Context, req ScreenRequest) (score.Result, error) {
	started := req.Received
	if started.IsZero() {
		started = time.Now()
	}
	msg, err := buildMessage(req)
	if err != nil {
		return score.Result{}, ErrParse
	}
	snap := sipmsg.SnapshotFrom(msg, req.SourceIP)
	en, verification := s.enrich(ctx, snap)
	signed := s.switchSigning(ctx, snap, req.Signing)
	en.SwitchSigns = signed != nil
	en.Network = s.network(en, fingerprint.Compute(msg))
	s.behaviour(ctx, req, snap, &en)
	result := s.Engine.Score(snap, en)
	decision := result
	result = s.hold(ctx, result)
	sample, trigger := s.Sampler.Decide(ctx, result, strings.TrimSpace(req.Customer))
	if sample {
		result.Sample = true
		result.Headers["X-Falcon-Sample"] = "1"
		result.Headers["X-Falcon-Sample-Seconds"] = strconv.Itoa(s.Sampler.Budget.ClipSeconds)
		result.Headers["X-Falcon-Sample-Reason"] = string(trigger)
	}
	latency := time.Since(started)

	ev := store.Event{
		ReceivedAt:  time.Now().UTC(),
		Action:      decision.Action,
		RiskScore:   result.RiskScore,
		SourceIP:    snap.SourceIP,
		From:        result.Signals.From,
		To:          result.Signals.To,
		CallID:      snap.CallID,
		UserAgent:   snap.UserAgent,
		Attest:      snap.Identity.Attest,
		Verstat:     result.Signals.Verstat,
		SignerSPC:   result.Signals.SignerSPC,
		SignerName:  result.Signals.SignerName,
		Provider:    result.Signals.IPProvider,
		Fingerprint: fingerprint.Compute(msg),
		Reasons:     result.Reasons,
		Switch:      req.Switch,
		Direction:   en.Direction,
		Customer:    strings.TrimSpace(req.Customer),
		Honeypot:    en.Honeypot,
		Sampled:     result.Sample,
		LatencyUS:   latency.Microseconds(),
		Held:        decision.Action != result.Action,
	}
	if ev.LatencyUS < 1 {
		ev.LatencyUS = 1
	}
	if s.Cfg.StoreRawSIP {
		ev.RawSIP = msg.Raw
	}
	if verification != nil {
		if b, err := json.Marshal(verification); err == nil {
			ev.Shaken = b
		}
	}
	if signed != nil {
		ev.Attest = signed.Attest
		ev.SignerSPC = signed.Signer.SPC
		ev.SignerName = firstNonEmpty(signed.Signer.Org, signed.Signer.CN)
		if b, err := json.Marshal(signed); err == nil {
			ev.Shaken = b
		}
	}
	if s.metrics != nil {
		s.metrics.observe(result, verification, latency)
		if decision.Action != result.Action {
			s.metrics.hold()
		}
	}
	go s.spoofAlert(ev, decision)
	go func(ev store.Event) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		id, err := s.Store.Insert(ctx, ev)
		if err != nil {
			log.Printf("falcon store: %v", err)
			return
		}
		ev.ID = id
		ev.RawSIP = ""
		if b, err := json.Marshal(ev); err == nil {
			s.hub.publish(b)
		}
	}(ev)

	return result, nil
}

// hold turns a reject or a challenge into an allow while monitor mode is
// on. The stored event keeps the real decision. The switch is told to
// continue, and X-Falcon-Monitor names what would have happened.
func (s *Server) hold(ctx context.Context, res score.Result) score.Result {
	if s.Mode(ctx) != config.ModeMonitor {
		return res
	}
	if res.Action != score.ActionReject && res.Action != score.ActionChallenge {
		return res
	}
	would := string(res.Action)
	res.Action = score.ActionAllow
	headers := make(map[string]string, len(res.Headers)+2)
	for k, v := range res.Headers {
		if k == "X-Falcon-Block" {
			continue
		}
		headers[k] = v
	}
	headers["X-Falcon-Monitor"] = would
	headers["X-Falcon-Action"] = string(score.ActionAllow)
	res.Headers = headers
	res.SIPStatus, res.SIPReason = score.ActionAllow.SIP()
	res.SwitchHints = score.ActionAllow.Hints()
	return res
}

// enrich gathers everything outside the SIP message: verification, operator
// rules, IP intel, and the paid CallerAPI signals.
func (s *Server) enrich(ctx context.Context, snap sipmsg.Snapshot) (score.Enrichment, *shaken.Result) {
	en := score.Enrichment{
		FeedEnabled: s.Cfg.FeedEnabled(),
		FirewallOn:  s.Cfg.FirewallEnabled(),
		FeedURL:     s.Cfg.UpsellFeedURL,
		FirewallURL: s.Cfg.UpsellFirewallURL,
	}
	var verification *shaken.Result
	if s.Verifier != nil && snap.Identity.Raw != "" {
		from := snap.PAIUser
		if from == "" {
			from = snap.FromUser
		}
		res := s.Verifier.Verify(ctx, snap.Identity.Raw, from, snap.ToUser)
		verification = &res
		en.Shaken = &score.Shaken{
			Verstat:    res.Verstat,
			Pending:    res.Pending,
			Revoked:    res.Revoked,
			SignerSPC:  res.Signer.SPC,
			SignerName: firstNonEmpty(res.Signer.Org, res.Signer.CN),
			Errors:     res.Errors,
		}
	}
	spc := ""
	if en.Shaken != nil {
		spc = en.Shaken.SignerSPC
	}
	if idx := s.ruleIndex(); idx != nil {
		if hit, ok := idx.Match(snap.FromUser, snap.SourceIP, spc); ok {
			en.List = &score.ListHit{Kind: string(hit.Kind), Subject: string(hit.Subject), Value: hit.Value, Note: hit.Note, RuleID: hit.ID}
		}
	}
	if s.IPIntel != nil && snap.SourceIP != "" {
		if m, ok := s.IPIntel.Lookup(snap.SourceIP); ok {
			en.IP = &score.IPIntel{Provider: m.Provider, Risk: string(m.Risk), Tags: m.Tags}
		}
	}
	if s.Feed != nil && s.Cfg.FeedEnabled() {
		en.FeedHit = s.Feed.Contains(snap.FromUser)
	}
	if s.Live != nil && s.Cfg.FirewallEnabled() && snap.FromUser != "" {
		fctx, fcancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		if lu, err := s.Live.Lookup(fctx, snap.FromUser); err == nil {
			en.FirewallSpam = lu.IsSpam || lu.SpamScore >= 70
		}
		fcancel()
	}
	if s.Live != nil && s.Cfg.BCIDEnabled() && snap.FromUser != "" && snap.ToUser != "" {
		vctx, vcancel := context.WithTimeout(ctx, 800*time.Millisecond)
		if v, err := s.Live.Verify(vctx, snap.FromUser, snap.ToUser, snap.BCIDAssertion); err == nil && v.Verdict != "" {
			row := &score.BCID{Verdict: v.Verdict, Action: v.Action, Reason: v.Reason}
			if v.Identity != nil {
				row.Name = v.Identity.Name
				row.Verified = v.Identity.Verified
				logo := v.Identity.LogoURL
				if strings.HasPrefix(logo, "/") {
					logo = strings.TrimRight(s.Cfg.CallerAPIBase, "/") + logo
				}
				row.LogoURL = logo
			}
			en.BCID = row
		}
		vcancel()
	}
	return en, verification
}

// switchSigning reads the certificate the switch reported it signs this
// call with. A PASSporT on the INVITE itself always wins.
func (s *Server) switchSigning(ctx context.Context, snap sipmsg.Snapshot, sg *Signing) *shaken.Result {
	if sg == nil || snap.Identity.Raw != "" {
		return nil
	}
	switch strings.ToUpper(strings.TrimSpace(sg.Attest)) {
	case "A", "B", "C":
	default:
		return nil
	}
	res := s.Verifier.Describe(ctx, sg.Attest, sg.OrigID, sg.X5U)
	return &res
}

// network reads the CallerAPI feed for the signer and the sending tool.
func (s *Server) network(en score.Enrichment, fp string) *score.Network {
	if s.Reputation == nil {
		return nil
	}
	var n score.Network
	n.Enforce = s.Cfg.ReputationEnforce
	if en.Shaken != nil {
		if sg, ok := s.Reputation.Signer(en.Shaken.SignerSPC); ok {
			n.SignerScore, n.SignerInstalls = sg.Score, sg.Installs
		}
	}
	if f, ok := s.Reputation.Fingerprint(fp); ok {
		n.FingerprintScore, n.FingerprintInstalls = f.Score, f.Installs
	}
	if n.SignerScore == 0 && n.FingerprintScore == 0 {
		return nil
	}
	return &n
}

func (s *Server) failOpen(w http.ResponseWriter, why string) {
	if !s.Cfg.FailOpen {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": why})
		return
	}
	writeJSON(w, http.StatusOK, score.Result{
		Action:    score.ActionAllow,
		RiskScore: 0,
		RiskBand:  "low",
		Reasons:   []score.Reason{{Code: "fail_open", Weight: 0, Detail: why, Category: "system"}},
		Headers:   map[string]string{"X-Falcon-Action": "allow", "X-Falcon-Score": "0"},
	})
}

func buildMessage(req ScreenRequest) (*sipmsg.Message, error) {
	if strings.TrimSpace(req.RawSIP) != "" {
		return sipmsg.Parse(req.RawSIP)
	}
	var b strings.Builder
	method := req.Method
	if method == "" {
		method = "INVITE"
	}
	uri := req.RequestURI
	if uri == "" {
		uri = "sip:unknown@localhost"
	}
	b.WriteString(method)
	b.WriteByte(' ')
	b.WriteString(uri)
	b.WriteString(" SIP/2.0\n")
	for k, v := range req.Headers {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(req.Body)
	return sipmsg.Parse(b.String())
}

func looksJSON(b []byte) bool {
	t := strings.TrimSpace(string(b))
	return strings.HasPrefix(t, "{")
}
