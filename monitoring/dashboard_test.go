package monitoring_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestFleetDashboardNamesTheMetrics(t *testing.T) {
	raw, err := os.ReadFile("grafana/dashboards/falcon.json")
	if err != nil {
		t.Fatal(err)
	}
	var dash struct {
		UID    string `json:"uid"`
		Title  string `json:"title"`
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatal(err)
	}
	if dash.UID != "falcon-fleet" || dash.Title != "Falcon fleet" {
		t.Fatalf("dashboard %+v", dash)
	}
	body := string(raw)
	for _, want := range []string{
		`"uid": "falcon"`,
		"falcon_screens_total",
		"falcon_screens_by_action_total",
		"falcon_hard_blocks_total",
		"falcon_screen_latency_seconds_sum",
		"falcon_shaken_verstat_total",
		"falcon_calls_answered_total",
		"falcon_uptime_seconds",
		`switch=~\"$switch\"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %s", want)
		}
	}
	if len(dash.Panels) < 8 {
		t.Fatalf("panels %d", len(dash.Panels))
	}

	prom, err := os.ReadFile("prometheus/prometheus.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(prom)
	for _, want := range []string{"job_name: falcon", "credentials_file: /etc/prometheus/falcon_token", "targets.yml", "refresh_interval: 30s"} {
		if !strings.Contains(text, want) {
			t.Errorf("prometheus config missing %s", want)
		}
	}
}
