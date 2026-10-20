package numbercheck

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNoKeyIsOff(t *testing.T) {
	c := New("https://api.example", " ")
	if c != nil {
		t.Fatal("a client without a key")
	}
	if _, err := c.View(context.Background(), ""); !errors.Is(err, ErrOff) {
		t.Fatalf("view on a nil client: %v", err)
	}
}

func TestCallsTheFixedPathsWithTheKey(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth") != "key-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		switch r.URL.Path {
		case basePath + "view":
			_, _ = io.WriteString(w, `{"columns":[{"key":"number","label":"Number"},{"key":"bad key","label":"x"},{"key":"status","label":"Status"}],
				"rows":[{"number":"+14155550100","status":"flagged","extra":"dropped"}],"stats":[{"label":"Numbers","value":"1"}]}`)
		case basePath + "import":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Errorf("multipart: %v", err)
			}
			f, _, err := r.FormFile("file")
			if err != nil {
				t.Errorf("file field: %v", err)
				return
			}
			body, _ := io.ReadAll(f)
			if string(body) != "+14155550100\n" {
				t.Errorf("file body %q", body)
			}
			_, _ = io.WriteString(w, `{"columns":[{"key":"number","label":"Number"}],"rows":[{"number":"+14155550100"}]}`)
		case basePath + "schedule":
			if r.Method == http.MethodPut {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"status":"error","message":"pick at least one day"}`)
				return
			}
			_, _ = io.WriteString(w, `{"enabled":false,"state":"off"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := New(srv.URL+"/", "key-1")
	ctx := context.Background()

	panel, err := c.View(ctx, "+1415<script>")
	if err != nil {
		t.Fatal(err)
	}
	if len(panel.Columns) != 2 || panel.Columns[1].Key != "status" {
		t.Fatalf("columns %+v", panel.Columns)
	}
	if len(panel.Rows) != 1 || panel.Rows[0]["status"] != "flagged" || panel.Rows[0]["extra"] != "" {
		t.Fatalf("rows %+v", panel.Rows)
	}
	if _, err := c.Import(ctx, []byte("+14155550100\n")); err != nil {
		t.Fatal(err)
	}
	if raw, err := c.Schedule(ctx); err != nil || !strings.Contains(string(raw), `"state":"off"`) {
		t.Fatalf("schedule %s %v", raw, err)
	}
	if _, err := c.SaveSchedule(ctx, []byte(`{"enabled":true,"weekdays":[]}`)); err == nil || err.Error() != "pick at least one day" {
		t.Fatalf("the CallerAPI message is not the error: %v", err)
	}
	if _, err := c.SaveSchedule(ctx, []byte(`{`)); err == nil {
		t.Fatal("invalid JSON was sent")
	}
	if len(seen) != 4 || seen[0] != "GET "+basePath+"view?q=" {
		t.Fatalf("requests %v", seen)
	}
}
