package sipserver

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/httpapi"
	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/sipmsg"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/voice"
)

const denied = "+13125550188"
const clean = "+13125550199"

func newFalcon(t *testing.T) *httpapi.Server {
	t.Helper()
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := &httpapi.Server{
		Cfg:       config.Config{FailOpen: true, RetentionDays: 30},
		Engine:    score.NewEngine(score.Thresholds{Flag: 40, Challenge: 60, Reject: 80}, score.Limits{Window: time.Minute, IP: 30, From: 20, Scan: 15}),
		Store:     db,
		InstallID: "test",
	}
	srv.Sampler = &voice.Sampler{Store: db, Budget: voice.DefaultBudget(), Enabled: true}
	ctx := context.Background()
	if err := srv.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddRule(ctx, lists.Rule{Kind: lists.Deny, Subject: lists.Number, Value: denied, Note: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.ReloadRules(ctx); err != nil {
		t.Fatal(err)
	}
	return srv
}

func start(t *testing.T, cfg Config) *Server {
	t.Helper()
	cfg.Listen = "127.0.0.1:0"
	cfg.Version = "test"
	s, err := New(cfg, newFalcon(t))
	if err != nil {
		t.Fatal(err)
	}
	// UDP and TCP bound to port 0 land on different ports. Tests read
	// each address.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx) }()
	return s
}

func invite(from string, vias ...string) string {
	if len(vias) == 0 {
		vias = []string{"SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK" + from + ";rport"}
	}
	var b strings.Builder
	b.WriteString("INVITE sip:+14155550100@carrier.example;user=phone SIP/2.0\r\n")
	for _, v := range vias {
		b.WriteString("Via: " + v + "\r\n")
	}
	b.WriteString("Max-Forwards: 70\r\n")
	b.WriteString("From: <sip:" + from + "@203.0.113.9>;tag=abc\r\n")
	b.WriteString("To: <sip:+14155550100@carrier.example>\r\n")
	b.WriteString("Call-ID: t-" + from + "@203.0.113.9\r\n")
	b.WriteString("CSeq: 1 INVITE\r\n")
	b.WriteString("Contact: <sip:" + from + "@203.0.113.9>\r\n")
	b.WriteString("User-Agent: sipserver-test/1.0\r\n")
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

// udpExchange sends one request and collects responses until a final one
// or the deadline.
func udpExchange(t *testing.T, to net.Addr, req string, wait time.Duration) []string {
	t.Helper()
	conn, err := net.Dial("udp", to.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	var out []string
	buf := make([]byte, 8192)
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return out
		}
		resp := string(buf[:n])
		out = append(out, resp)
		if !strings.HasPrefix(resp, "SIP/2.0 1") {
			return out
		}
	}
}

func statusOf(resp string) string {
	f := strings.Fields(strings.SplitN(resp, "\r\n", 2)[0])
	if len(f) < 2 {
		return ""
	}
	return f[1]
}

func header(resp, name string) string {
	for _, l := range strings.Split(resp, "\r\n") {
		k, v, ok := strings.Cut(l, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func TestMonitorRedirectContinuesADeniedCall(t *testing.T) {
	api := newFalcon(t)
	api.Cfg.Mode = config.ModeMonitor
	s, err := New(Config{Listen: "127.0.0.1:0", Version: "test"}, api)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx) }()

	got := udpExchange(t, s.UDPAddr(), invite(denied), 3*time.Second)
	if len(got) < 2 || statusOf(got[len(got)-1]) != "302" {
		t.Fatalf("monitor must continue a denied call: %q", got)
	}
	final := got[len(got)-1]
	if header(final, "X-Falcon-Action") != "allow" || header(final, "X-Falcon-Monitor") != "reject" {
		t.Fatalf("headers: %s", final)
	}
	if header(final, "X-Falcon-Block") != "" {
		t.Fatalf("monitor must not send a block header: %s", final)
	}
}

func TestUDPRejectAndRedirect(t *testing.T) {
	s := start(t, Config{})

	got := udpExchange(t, s.UDPAddr(), invite(denied), 3*time.Second)
	if len(got) < 2 || statusOf(got[0]) != "100" || statusOf(got[len(got)-1]) != "603" {
		t.Fatalf("denied: %q", got)
	}
	final := got[len(got)-1]
	if header(final, "X-Falcon-Action") != "reject" || !strings.Contains(header(final, "X-Falcon-Reasons"), "denylist") {
		t.Fatalf("headers: %s", final)
	}
	if header(final, "Contact") != "" {
		t.Fatalf("reject must not carry Contact: %s", final)
	}
	if !strings.Contains(header(final, "To"), ";tag=") {
		t.Fatalf("final needs a To tag: %s", final)
	}
	if header(final, "Via") != "SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK"+denied+";rport" {
		t.Fatalf("via not echoed: %s", final)
	}

	got = udpExchange(t, s.UDPAddr(), invite(clean), 3*time.Second)
	if len(got) < 2 || statusOf(got[len(got)-1]) != "302" {
		t.Fatalf("clean: %q", got)
	}
	final = got[len(got)-1]
	if header(final, "Contact") != "<sip:+14155550100@carrier.example;user=phone>" {
		t.Fatalf("contact: %s", final)
	}
	if header(final, "X-Falcon-Action") != "allow" {
		t.Fatalf("action: %s", final)
	}
}

func TestRedirectHostRewrite(t *testing.T) {
	s := start(t, Config{RedirectHost: "10.0.0.5:5080"})
	got := udpExchange(t, s.UDPAddr(), invite(clean), 3*time.Second)
	final := got[len(got)-1]
	if statusOf(final) != "302" || header(final, "Contact") != "<sip:+14155550100@10.0.0.5:5080;user=phone>" {
		t.Fatalf("contact: %s", final)
	}
}

func TestRetransmitGetsSameFinal(t *testing.T) {
	s := start(t, Config{})
	first := udpExchange(t, s.UDPAddr(), invite(denied), 3*time.Second)
	again := udpExchange(t, s.UDPAddr(), invite(denied), 3*time.Second)
	if len(again) != 1 {
		t.Fatalf("retransmit must get only the cached final, got %d responses", len(again))
	}
	if first[len(first)-1] != again[0] {
		t.Fatalf("retransmit differs:\n%s\n---\n%s", first[len(first)-1], again[0])
	}
}

func TestOptionsAckCancelAndUnknown(t *testing.T) {
	s := start(t, Config{})
	base := "Via: SIP/2.0/UDP 203.0.113.9;branch=z9hG4bKopt\r\nFrom: <sip:ping@x>;tag=1\r\nTo: <sip:falcon@y>\r\nCall-ID: opt1\r\n"

	got := udpExchange(t, s.UDPAddr(), "OPTIONS sip:falcon@y SIP/2.0\r\n"+base+"CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n", time.Second)
	if len(got) != 1 || statusOf(got[0]) != "200" || !strings.Contains(header(got[0], "Allow"), "INVITE") {
		t.Fatalf("options: %q", got)
	}

	got = udpExchange(t, s.UDPAddr(), "ACK sip:falcon@y SIP/2.0\r\n"+base+"CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n", 300*time.Millisecond)
	if len(got) != 0 {
		t.Fatalf("ack must be silent: %q", got)
	}

	got = udpExchange(t, s.UDPAddr(), "CANCEL sip:falcon@y SIP/2.0\r\n"+base+"CSeq: 1 CANCEL\r\nContent-Length: 0\r\n\r\n", time.Second)
	if len(got) != 1 || statusOf(got[0]) != "481" {
		t.Fatalf("cancel of unknown: %q", got)
	}

	got = udpExchange(t, s.UDPAddr(), "REGISTER sip:falcon@y SIP/2.0\r\n"+base+"CSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n", time.Second)
	if len(got) != 1 || statusOf(got[0]) != "405" {
		t.Fatalf("register: %q", got)
	}
}

func TestPeerOutsideAllowlistIsDropped(t *testing.T) {
	s := start(t, Config{Peers: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})
	got := udpExchange(t, s.UDPAddr(), invite(denied), 500*time.Millisecond)
	if len(got) != 0 {
		t.Fatalf("loopback is outside the allowlist and must get nothing: %q", got)
	}
	if s.Dropped() != 1 {
		t.Fatalf("dropped = %d", s.Dropped())
	}
}

func TestTCPFramingAndKeepAlive(t *testing.T) {
	s := start(t, Config{})
	conn, err := net.Dial("tcp", s.TCPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rd := bufio.NewReader(conn)
	read := func() string {
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		raw, err := readFrame(rd)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	// Two requests on one connection, the second with a body.
	if _, err := conn.Write([]byte(invite(denied, "SIP/2.0/TCP 203.0.113.9:5060;branch=z9hG4bKtcp1"))); err != nil {
		t.Fatal(err)
	}
	if got := statusOf(read()); got != "100" {
		t.Fatalf("first provisional: %s", got)
	}
	final := read()
	if statusOf(final) != "603" || header(final, "X-Falcon-Action") != "reject" {
		t.Fatalf("tcp deny: %s", final)
	}
	sdp := "v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\nc=IN IP4 203.0.113.9\r\nm=audio 4000 RTP/AVP 0\r\n"
	withBody := strings.Replace(invite(clean, "SIP/2.0/TCP 203.0.113.9:5060;branch=z9hG4bKtcp2"), "Content-Length: 0\r\n\r\n", fmt.Sprintf("Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(sdp), sdp), 1)
	if _, err := conn.Write([]byte(withBody)); err != nil {
		t.Fatal(err)
	}
	if got := statusOf(read()); got != "100" {
		t.Fatalf("second provisional: %s", got)
	}
	final = read()
	if statusOf(final) != "302" {
		t.Fatalf("tcp allow: %s", final)
	}
}

func TestSourceIPFromViaAndHeader(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.1")
	m := mustParse(t, invite(clean,
		"SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKa",
		"SIP/2.0/UDP 192.0.2.7:5060;received=198.51.100.3;branch=z9hG4bKb",
	))
	if got := sourceIP(m, peer); got != "198.51.100.3" {
		t.Fatalf("received= wins: %s", got)
	}
	m = mustParse(t, invite(clean, "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKa, SIP/2.0/TCP [2001:db8::9]:5061;branch=z9hG4bKb"))
	if got := sourceIP(m, peer); got != "2001:db8::9" {
		t.Fatalf("comma hop host: %s", got)
	}
	m = mustParse(t, invite(clean))
	if got := sourceIP(m, peer); got != "10.0.0.1" {
		t.Fatalf("single via falls back to peer: %s", got)
	}
	m = mustParse(t, strings.Replace(invite(clean), "Max-Forwards: 70\r\n", "Max-Forwards: 70\r\nX-Source-IP: 203.0.113.77:5060\r\n", 1))
	if got := sourceIP(m, peer); got != "203.0.113.77" {
		t.Fatalf("explicit header wins: %s", got)
	}
}

func TestParsePeers(t *testing.T) {
	got, err := ParsePeers(" 10.0.0.1, 192.0.2.0/24 ,2001:db8::1 ")
	if err != nil || len(got) != 3 || got[0].Bits() != 32 || got[1].Bits() != 24 || got[2].Bits() != 128 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParsePeers("switch.example"); err == nil {
		t.Fatal("hostnames are not accepted")
	}
}

func mustParse(t *testing.T, raw string) *sipmsg.Message {
	t.Helper()
	m, err := sipmsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
