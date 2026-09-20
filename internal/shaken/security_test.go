package shaken

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A PASSporT can name any URL. Production policy must refuse anything that
// is not https to a public address before a single packet leaves the host.
func TestX5UToPrivateAddressIsRefusedInProduction(t *testing.T) {
	p := newPKI(t, "1234")
	v := New(trustWithRoot(p), DefaultOptions()) // production policy
	for _, x5u := range []string{
		"https://169.254.169.254/latest/meta-data/iam/",
		"https://10.0.0.5/cert.pem",
		"https://127.0.0.1:8443/cert.pem",
		"https://sbc.internal/cert.pem",
		"http://certs.example.com/cert.pem",
	} {
		id := p.passport(t, x5u, "A", "14155550100", "15551212", time.Now().Unix())
		r := v.Verify(context.Background(), id, "", "")
		if r.Verstat != VerstatFailed || !strings.Contains(strings.Join(r.Errors, " "), "x5u rejected") {
			t.Fatalf("%s must be refused: %+v", x5u, r)
		}
		if certs, inflight := v.CacheStats(); certs != 0 || inflight != 0 {
			t.Fatalf("%s must not start a fetch: certs=%d inflight=%d", x5u, certs, inflight)
		}
	}
}

// A burst of unique x5u values is bounded by the per-second bucket. Excess
// fetches are refused and remembered briefly so the switch is never held.
func TestFetchLimiterThrottlesUniqueURLs(t *testing.T) {
	p := newPKI(t, "1234")
	var served int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		_, _ = w.Write(p.chainPEM)
	}))
	defer srv.Close()
	opts := DefaultOptions()
	opts.AllowHTTP = true
	opts.Budget = 2 * time.Second
	opts.MaxFetchPerSecond = 2
	v := New(trustWithRoot(p), opts)

	passed, throttled := 0, 0
	for i := 0; i < 6; i++ {
		id := p.passport(t, srv.URL+"/c"+string(rune('a'+i))+".pem", "A", "14155550100", "15551212", time.Now().Unix())
		r := v.Verify(context.Background(), id, "", "")
		switch {
		case r.Verstat == VerstatPassed:
			passed++
		case strings.Contains(strings.Join(r.Errors, " "), "throttled"):
			throttled++
		default:
			t.Fatalf("unexpected result: %+v", r)
		}
	}
	if passed != 2 || throttled != 4 || served != 2 {
		t.Fatalf("passed=%d throttled=%d served=%d", passed, throttled, served)
	}
}
