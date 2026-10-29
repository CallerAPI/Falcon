package cliwithhold

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdaptersHideCallerIDFromTheHeader(t *testing.T) {
	root := "."
	checks := []struct {
		file    string
		needles []string
	}{
		{"kamailio/falcon.cfg", []string{`headers.Privacy`, `X-Falcon-CLI-Withhold`, `$fU = "anonymous"`, `Privacy: id`}},
		{"kamailio/falcon_async.cfg", []string{`headers.Privacy`, `X-Falcon-CLI-Withhold`, `$fU = "anonymous"`, `Privacy: id`}},
		{"opensips/falcon.cfg", []string{`headers/Privacy`, `X-Falcon-CLI-Withhold`, `$fU = "anonymous"`, `Privacy: id`}},
		{"opensips/falcon_async.cfg", []string{`headers/Privacy`, `X-Falcon-CLI-Withhold`, `$fU = "anonymous"`, `Privacy: id`}},
		{"asterisk/falcon.agi", []string{`"Privacy"`, `X-Falcon-CLI-Withhold`, `CALLERID(num-pres)`, `prohib`}},
		{"freeswitch/falcon.lua", []string{`Privacy`, `X-Falcon-CLI-Withhold`, `privacy`, `full`}},
	}
	for _, c := range checks {
		b, err := os.ReadFile(filepath.Join(root, c.file))
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		for _, n := range c.needles {
			if !strings.Contains(text, n) {
				t.Errorf("%s missing %q", c.file, n)
			}
		}
	}
}

func TestAsteriskAGISetsPresentationProhibited(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	withhold := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","risk_score":15,"headers_to_set":{"X-Falcon-CLI-Withhold":"1"}}`))
	}))
	defer withhold.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","risk_score":15,"headers_to_set":{}}`))
	}))
	defer plain.Close()

	hidden := runAGI(t, python, withhold.URL)
	if hidden["CALLERID(num-pres)"] != "prohib" {
		t.Fatalf("withhold sets %v", hidden)
	}
	open := runAGI(t, python, plain.URL)
	if _, ok := open["CALLERID(num-pres)"]; ok {
		t.Fatalf("plain call hid the caller ID: %v", open)
	}
}

func TestFreeSWITCHHidesTheNumber(t *testing.T) {
	lua, err := exec.LookPath("lua5.4")
	if err != nil {
		lua, err = exec.LookPath("lua")
	}
	if err != nil {
		t.Skip("lua is not installed")
	}
	for _, arg := range []string{"1", "0"} {
		cmd := exec.Command(lua, "e2e/cli_harness.lua", arg)
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "PASS") {
			t.Fatalf("arg %s: %v\n%s", arg, err, out)
		}
	}
}

func runAGI(t *testing.T, python, url string) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "asterisk/falcon.agi")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "FALCON_URL="+url, "FALCON_TOKEN=secret")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte("agi_request: falcon.agi\nagi_channel: PJSIP/trunk-1\n\n")); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"EXTEN":                           "+14155550100",
		"CHANNEL(pjsip,remote_addr)":      "203.0.113.9:5060",
		"PJSIP_HEADER(read,From)":         "<sip:+447700900123@203.0.113.9>;tag=1",
		"PJSIP_HEADER(read,To)":           "<sip:+14155550100@carrier.example>",
		"PJSIP_HEADER(read,Call-ID)":      "agi-cli",
		"PJSIP_HEADER(read,User-Agent)":   "cli-test",
		"PJSIP_HEADER(read,Privacy)":      "none",
		"PJSIP_HEADER(read,Content-Type)": "application/sdp",
	}
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 128)
	sets := map[string]string{}
	for {
		n, err := stdout.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		for {
			i := strings.IndexByte(string(buf), '\n')
			if i < 0 {
				break
			}
			line := strings.TrimSpace(string(buf[:i]))
			buf = buf[i+1:]
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "GET VARIABLE ") {
				name := strings.Trim(strings.TrimPrefix(line, "GET VARIABLE "), `"`)
				value := vars[name]
				reply := "200 result=0\n"
				if value != "" {
					reply = "200 result=1 (" + value + ")\n"
				}
				if _, err := stdin.Write([]byte(reply)); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if strings.HasPrefix(line, "SET VARIABLE ") {
				rest := strings.TrimPrefix(line, "SET VARIABLE ")
				name, value, _ := strings.Cut(rest, " ")
				sets[name] = strings.Trim(value, `"`)
				if _, err := stdin.Write([]byte("200 result=1\n")); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if _, err := stdin.Write([]byte("200 result=1\n")); err != nil {
				t.Fatal(err)
			}
		}
		if err != nil {
			break
		}
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	return sets
}
