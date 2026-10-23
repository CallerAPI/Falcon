package sipguard

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emiago/sipgo/sip"
)

// ParseLogEvery is the shortest gap between two guarded lines for one key.
const ParseLogEvery = 10 * time.Second

// parseFailure is the message sipgo logs when a message does not parse.
const parseFailure = "failed to parse"

// guarded maps sipgo messages whose attributes can quote a message to the
// fixed line that replaces them. These lines are rate limited.
var guarded = map[string]string{
	parseFailure:                         "sip message did not parse, dropped",
	"Server tx failed to handle request": "sip request could not be handled, dropped",
	"Failed to send stateless 400 for malformed request": "sip error reply not sent",
	"Client tx failed to handle response":                "sip response could not be handled, dropped",
}

// allowedKeys are the only attribute keys a sipgo record keeps. Any other
// key can hold SIP content. The error value is replaced by a category.
var allowedKeys = map[string]bool{"caller": true, "laddr": true, "network": true, "method": true, "dur": true, "error": true}

var (
	parseFailures      atomic.Uint64
	unhandledResponses atomic.Uint64
)

// ParseFailures returns how many SIP messages failed to parse since the
// process started, including the ones whose log line was suppressed.
func ParseFailures() uint64 {
	return parseFailures.Load()
}

// UnhandledResponse counts a response that matched no transaction. It
// logs nothing. Pass it to sip.WithTransactionLayerUnhandledResponseHandler.
func UnhandledResponse(*sip.Response) {
	unhandledResponses.Add(1)
}

// UnhandledResponses returns how many responses matched no transaction
// since the process started.
func UnhandledResponses() uint64 {
	return unhandledResponses.Load()
}

// LogHandler wraps the handler of a sipgo logger. A record keeps only the
// attributes in allowedKeys, also inside inline groups and after a
// LogValuer resolves. Named groups are dropped. An error becomes a fixed
// category with no error text.
//
// A guarded message keeps none of its attributes. It becomes one fixed
// line with the caller, a reason, and the count of lines suppressed since
// the last one. One caller and message pair logs at most one line per
// interval. sipgo sets the caller per transport and per layer. It does
// not attach the source address to the record.
type LogHandler struct {
	inner  slog.Handler
	caller string
	lim    *limiter
}

// NewLogHandler wraps inner. every is the shortest gap between two
// guarded lines for one key. A zero or negative value uses ParseLogEvery.
func NewLogHandler(inner slog.Handler, every time.Duration) *LogHandler {
	if every <= 0 {
		every = ParseLogEvery
	}
	return &LogHandler{inner: inner, lim: &limiter{every: every, now: time.Now, seen: map[string]*window{}}}
}

func (h *LogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *LogHandler) Handle(ctx context.Context, r slog.Record) error {
	if line, ok := guarded[r.Message]; ok {
		return h.guarded(ctx, r, line)
	}
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	var attrs []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	out.AddAttrs(allowed(attrs, nil)...)
	return h.inner.Handle(ctx, out)
}

func (h *LogHandler) guarded(ctx context.Context, r slog.Record, line string) error {
	if r.Message == parseFailure {
		parseFailures.Add(1)
	}
	caller := h.caller
	var cause any
	r.Attrs(func(a slog.Attr) bool {
		v := a.Value.Resolve()
		switch a.Key {
		case "caller":
			if v.Kind() == slog.KindString {
				caller = v.String()
			}
		case "error":
			cause = v.Any()
		}
		return true
	})
	ok, suppressed := h.lim.allow(caller + "\x00" + r.Message)
	if !ok {
		return nil
	}
	reason := errorCategory(cause)
	if r.Message == parseFailure {
		reason = parseReason(cause)
	}
	out := slog.NewRecord(r.Time, r.Level, line, r.PC)
	out.AddAttrs(slog.String("reason", reason))
	if suppressed > 0 {
		out.AddAttrs(slog.Uint64("suppressed", suppressed))
	}
	return h.inner.Handle(ctx, out)
}

func (h *LogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	kept := allowed(attrs, nil)
	caller := h.caller
	for _, a := range kept {
		if a.Key == "caller" && a.Value.Kind() == slog.KindString {
			caller = a.Value.String()
		}
	}
	return &LogHandler{inner: h.inner.WithAttrs(kept), caller: caller, lim: h.lim}
}

func (h *LogHandler) WithGroup(name string) slog.Handler {
	return &LogHandler{inner: h.inner.WithGroup(name), caller: h.caller, lim: h.lim}
}

// allowed appends to dst the attributes of attrs whose key is allowed.
// Values are resolved first. An inline group is filtered member by member.
// A named group is dropped.
func allowed(attrs []slog.Attr, dst []slog.Attr) []slog.Attr {
	for _, a := range attrs {
		v := a.Value.Resolve()
		if v.Kind() == slog.KindGroup {
			if a.Key == "" {
				dst = allowed(v.Group(), dst)
			}
			continue
		}
		if !allowedKeys[a.Key] {
			continue
		}
		if a.Key == "error" {
			dst = append(dst, slog.String("error", errorCategory(v.Any())))
			continue
		}
		dst = append(dst, slog.Attr{Key: a.Key, Value: v})
	}
	return dst
}

// parseReason names a sipgo parse error without its text.
func parseReason(cause any) string {
	err, _ := cause.(error)
	switch {
	case errors.Is(err, sip.ErrMessageTooLarge):
		return "too large"
	case errors.Is(err, sip.ErrParseReadBodyIncomplete):
		return "incomplete body"
	case errors.Is(err, sip.ErrParseLineNoCRLF):
		return "no line end"
	case errors.Is(err, sip.ErrParseEOF):
		return "truncated"
	default:
		return "malformed"
	}
}

// errorCategory names an error without its text.
func errorCategory(cause any) string {
	err, ok := cause.(error)
	if !ok || err == nil {
		return "error"
	}
	var ne net.Error
	switch {
	case errors.Is(err, sip.ErrTransactionTimeout), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, sip.ErrTransactionCanceled), errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, sip.ErrTransactionTerminated):
		return "terminated"
	case errors.Is(err, sip.ErrTransactionTransport), errors.Is(err, sip.ErrUDPMTUCongestion), errors.Is(err, sip.ErrTransportNotSuported):
		return "transport"
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.EOF):
		return "closed"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case strings.HasPrefix(err.Error(), "make key failed"):
		return "malformed"
	default:
		return "error"
	}
}

// limiter allows one line per key per interval and counts the rest. The
// keys are fixed caller and message pairs, so the map stays small.
type limiter struct {
	mu    sync.Mutex
	every time.Duration
	now   func() time.Time
	seen  map[string]*window
}

type window struct {
	last       time.Time
	suppressed uint64
}

// allow reports whether key may log now. When it may, it also returns how
// many lines for key were suppressed since the last allowed one.
func (l *limiter) allow(key string) (bool, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	w := l.seen[key]
	if w == nil {
		l.seen[key] = &window{last: now}
		return true, 0
	}
	if now.Sub(w.last) < l.every {
		w.suppressed++
		return false, 0
	}
	n := w.suppressed
	w.last, w.suppressed = now, 0
	return true, n
}
