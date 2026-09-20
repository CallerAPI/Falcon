package safehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestValidateURLRejectsUnsafeTargets(t *testing.T) {
	p := DefaultPolicy()
	bad := []string{
		"http://example.com/cert.pem",         // plain http in production
		"ftp://example.com/cert.pem",          // scheme
		"https://127.0.0.1/cert.pem",          // loopback literal
		"https://[::1]/cert.pem",              // v6 loopback
		"https://10.0.0.5/cert.pem",           // private
		"https://169.254.169.254/latest/meta", // cloud metadata
		"https://100.64.1.1/cert.pem",         // carrier NAT
		"https://localhost/cert.pem",          // loopback name
		"https://sbc.internal/cert.pem",       // internal suffix
		"https://user:pass@example.com/c.pem", // credentials in url
		"https://example.com:99999/cert.pem",  // bad port
		"https:///cert.pem",                   // no host
		"https://[fe80::1]/cert.pem",          // link local v6
		"https://192.0.2.10/cert.pem",         // documentation range
	}
	for _, u := range bad {
		if _, err := p.ValidateURL(u); err == nil {
			t.Fatalf("%s must be rejected", u)
		}
	}
	good := []string{"https://certs.example.com/cert.pem", "https://8.8.8.8/cert.pem", "https://certs.example.com:8443/a/b.pem"}
	for _, u := range good {
		if _, err := p.ValidateURL(u); err != nil {
			t.Fatalf("%s must be accepted: %v", u, err)
		}
	}
}

func TestIsPublic(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.5.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1", "64:ff9b::a00:1"} {
		if IsPublic(netip.MustParseAddr(s)) {
			t.Fatalf("%s must not be public", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "104.16.0.1"} {
		if !IsPublic(netip.MustParseAddr(s)) {
			t.Fatalf("%s must be public", s)
		}
	}
}

// The dial-time control rejects a private destination even when the URL
// looked fine, which is what stops DNS rebinding.
func TestClientRefusesPrivateDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("secret")) }))
	defer srv.Close()
	p := DefaultPolicy()
	p.AllowHTTP = true // the URL passes; the dial must still fail on 127.0.0.1
	_, _, err := p.Get(context.Background(), p.Client(), srv.URL, "")
	if err == nil || !strings.Contains(err.Error(), "not public") {
		t.Fatalf("private dial must fail, got %v", err)
	}
	p.AllowPrivate = true
	body, status, err := p.Get(context.Background(), p.Client(), srv.URL, "")
	if err != nil || status != 200 || string(body) != "secret" {
		t.Fatalf("lab policy must reach loopback: %v %d %q", err, status, body)
	}
}

func TestRedirectsAreValidatedAndBounded(t *testing.T) {
	var target string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hop":
			http.Redirect(w, r, target, http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	p := DefaultPolicy()
	p.AllowHTTP = true
	p.AllowPrivate = true
	client := p.Client()

	target = "http://169.254.169.254/latest/meta-data/"
	p.AllowPrivate = false
	if _, _, err := p.Get(context.Background(), client, srv.URL+"/hop", ""); err == nil {
		t.Fatal("redirect to metadata must fail")
	}
	p.AllowPrivate = true
	client = p.Client()
	target = "ftp://example.com/"
	if _, _, err := p.Get(context.Background(), client, srv.URL+"/hop", ""); err == nil {
		t.Fatal("redirect to ftp must fail")
	}
	if _, _, err := p.Get(context.Background(), client, srv.URL+"/loop", ""); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("redirect loop must stop: %v", err)
	}
}

func TestBodyCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(make([]byte, 100*1024)) }))
	defer srv.Close()
	p := DefaultPolicy()
	p.AllowHTTP, p.AllowPrivate = true, true
	if _, _, err := p.Get(context.Background(), p.Client(), srv.URL, ""); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized body must fail: %v", err)
	}
}
