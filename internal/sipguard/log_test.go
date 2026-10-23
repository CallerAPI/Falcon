package sipguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

const malformed = "INVITE sip:+14155550100@127.0.0.1 SIP/2.0 x\r\n" +
	"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKbad\r\n" +
	"From: <sip:+13125550188@127.0.0.1>;tag=1\r\n" +
	"Call-ID: bad\r\n" +
	"CSeq: 1 INVITE\r\n" +
	"Content-Length: 0\r\n\r\n"

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestLogger(every time.Duration) (*slog.Logger, *syncBuffer, *clock) {
	out := &syncBuffer{}
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	h := NewLogHandler(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelError}), every)
	h.lim.now = c.now
	return slog.New(h), out, c
}

func parseError(t *testing.T) error {
	t.Helper()
	_, err := sip.NewParser().ParseSIP([]byte(malformed))
	if err == nil {
		t.Fatal("the malformed message parsed")
	}
	return err
}

func assertNoRaw(t *testing.T, out string) {
	t.Helper()
	for _, raw := range []string{"+1312555", "+1415555", "INVITE", "Via", "SIP/2.0", "z9hG4bK", "Call-ID"} {
		if strings.Contains(out, raw) {
			t.Fatalf("log carries %q:\n%s", raw, out)
		}
	}
}

func TestLogHandlerDropsTheRawMessageOfAParseFailure(t *testing.T) {
	log, out, _ := newTestLogger(time.Minute)
	err := parseError(t)
	log.With("caller", "Transport<UDP>").Error("failed to parse", "data", malformed, "error", err)

	got := out.String()
	assertNoRaw(t, got)
	if strings.Contains(got, err.Error()) {
		t.Fatalf("log carries the parser error text:\n%s", got)
	}
	if !strings.Contains(got, "did not parse") || !strings.Contains(got, "caller=Transport<UDP>") || !strings.Contains(got, "reason=") {
		t.Fatalf("parse failure line missing its fields:\n%s", got)
	}
}

func TestLogHandlerRateLimitsParseFailuresPerTransport(t *testing.T) {
	log, out, c := newTestLogger(10 * time.Second)
	err := parseError(t)
	udp := log.With("caller", "Transport<UDP>")
	tcp := log.With("caller", "Transport<TCP>")
	for i := 0; i < 50; i++ {
		udp.Error("failed to parse", "data", malformed, "error", err)
	}
	tcp.Error("failed to parse", "error", err, "data", malformed)
	if n := strings.Count(out.String(), "did not parse"); n != 2 {
		t.Fatalf("want one line per transport, got %d:\n%s", n, out.String())
	}

	c.t = c.t.Add(9 * time.Second)
	udp.Error("failed to parse", "data", malformed, "error", err)
	if n := strings.Count(out.String(), "did not parse"); n != 2 {
		t.Fatalf("a line inside the interval was logged:\n%s", out.String())
	}

	c.t = c.t.Add(2 * time.Second)
	udp.Error("failed to parse", "data", malformed, "error", err)
	got := out.String()
	if n := strings.Count(got, "did not parse"); n != 3 {
		t.Fatalf("want a line after the interval, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "suppressed=50") {
		t.Fatalf("suppressed count missing:\n%s", got)
	}
	assertNoRaw(t, got)
}

func TestLogHandlerKeepsOnlyAllowedKeys(t *testing.T) {
	log, out, _ := newTestLogger(time.Minute)
	req := "INVITE sip:+14155550100@127.0.0.1 SIP/2.0"
	log.With("data", malformed, "caller", "TransactionLayer").Error("send failed",
		"msg", malformed, "req", req, "res", req, "reason", req, "tx", req, "fsmError", req,
		"callid", "bad", "invite_request", req, "invite_response", req, "cancel_request", req,
		"other", req, "laddr", "127.0.0.1:5060", "network", "udp", "method", "INVITE", "dur", time.Second,
		"error", errors.New(req))
	got := out.String()
	assertNoRaw(t, strings.ReplaceAll(got, "method=INVITE", ""))
	for _, want := range []string{"send failed", "caller=TransactionLayer", "laddr=127.0.0.1:5060", "network=udp", "method=INVITE", "dur=1s", "error=error"} {
		if !strings.Contains(got, want) {
			t.Fatalf("record lost %q:\n%s", want, got)
		}
	}
	for _, key := range []string{"data=", "msg=\"I", "req=", "res=", "reason=", "tx=", "fsmError=", "callid=", "invite_request=", "invite_response=", "cancel_request=", "other="} {
		if strings.Contains(got, key) {
			t.Fatalf("record kept %q:\n%s", key, got)
		}
	}
}

type valuer struct{ v slog.Value }

func (v valuer) LogValue() slog.Value { return v.v }

func TestLogHandlerFiltersGroupsAndLogValuers(t *testing.T) {
	log, out, _ := newTestLogger(time.Minute)
	req := "INVITE sip:+14155550100@127.0.0.1 SIP/2.0"
	log.Error("grouped",
		slog.Group("caller", slog.String("req", req)),
		slog.Group("", slog.String("req", req), slog.String("network", "udp")),
		slog.Any("method", valuer{slog.GroupValue(slog.String("req", req))}),
		slog.Any("", valuer{slog.GroupValue(slog.String("callid", req), slog.String("dur", "2s"))}),
		slog.Any("laddr", valuer{slog.StringValue("127.0.0.1:5060")}),
		slog.Any("req", valuer{slog.StringValue(req)}),
	)
	slog.New(log.Handler().WithAttrs([]slog.Attr{slog.Group("", slog.String("tx", req))})).Error("grouped again")
	got := out.String()
	assertNoRaw(t, got)
	for _, want := range []string{"network=udp", "dur=2s", "laddr=127.0.0.1:5060", "grouped again"} {
		if !strings.Contains(got, want) {
			t.Fatalf("record lost %q:\n%s", want, got)
		}
	}
	for _, key := range []string{"req=", "callid=", "tx=", "caller.", "method."} {
		if strings.Contains(got, key) {
			t.Fatalf("record kept %q:\n%s", key, got)
		}
	}
}

func TestLogHandlerGuardsRequestFailures(t *testing.T) {
	log, out, _ := newTestLogger(time.Minute)
	txl := log.With("caller", "TransactionLayer")
	req := "INVITE sip:+14155550100@127.0.0.1 SIP/2.0"
	keyErr := fmt.Errorf("make key failed: %w", errors.New("'Via' header not found or empty in message '"+req+"'"))
	for i := 0; i < 5; i++ {
		txl.Error("Server tx failed to handle request", "error", keyErr, "req", req)
		txl.Error("Failed to send stateless 400 for malformed request", "error", keyErr, "reason", keyErr.Error(), "req", req)
		txl.Error("Client tx failed to handle response", "error", keyErr)
	}
	got := out.String()
	assertNoRaw(t, got)
	for _, line := range []string{`msg="sip request could not be handled, dropped" caller=TransactionLayer reason=malformed`, `msg="sip error reply not sent"`, `msg="sip response could not be handled, dropped"`} {
		if n := strings.Count(got, line); n != 1 {
			t.Fatalf("want one %q line, got %d:\n%s", line, n, got)
		}
	}
}

func TestParseFailureCounterCountsSuppressedLines(t *testing.T) {
	log, out, _ := newTestLogger(time.Minute)
	err := parseError(t)
	before := ParseFailures()
	for i := 0; i < 30; i++ {
		log.Error("failed to parse", "data", malformed, "error", err)
	}
	if got := ParseFailures() - before; got != 30 {
		t.Fatalf("counter moved by %d, want 30", got)
	}
	if n := strings.Count(out.String(), "did not parse"); n != 1 {
		t.Fatalf("want one line, got %d", n)
	}
}

func TestErrorCategoryHasNoText(t *testing.T) {
	cases := map[string]any{
		"timeout":    fmt.Errorf("x: %w", sip.ErrTransactionTimeout),
		"canceled":   context.Canceled,
		"terminated": sip.ErrTransactionTerminated,
		"transport":  sip.ErrUDPMTUCongestion,
		"closed":     net.ErrClosed,
		"malformed":  errors.New("make key failed: +14155550100"),
		"error":      errors.New("+14155550100"),
	}
	for want, err := range cases {
		if got := errorCategory(err); got != want {
			t.Fatalf("%v: got %q, want %q", err, got, want)
		}
	}
	if got := errorCategory("+14155550100"); got != "error" {
		t.Fatalf("string error: got %q", got)
	}
}

func TestLogHandlerKeepsTheInnerLevel(t *testing.T) {
	log, out, _ := newTestLogger(time.Minute)
	log.Info("failed to parse", "data", malformed)
	log.Debug("Keep alive CRLF received")
	if got := out.String(); got != "" {
		t.Fatalf("records below the inner level were logged:\n%s", got)
	}
}

func TestParseReasonNamesSentinels(t *testing.T) {
	cases := map[error]string{
		sip.ErrMessageTooLarge:         "too large",
		sip.ErrParseReadBodyIncomplete: "incomplete body",
		sip.ErrParseLineNoCRLF:         "no line end",
		sip.ErrParseEOF:                "truncated",
	}
	for err, want := range cases {
		if got := parseReason(err); got != want {
			t.Fatalf("%v: got %q, want %q", err, got, want)
		}
	}
	if got := parseReason(parseError(t)); got != "malformed" {
		t.Fatalf("header error: got %q", got)
	}
}
