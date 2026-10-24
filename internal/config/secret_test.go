package config

import "testing"

func TestCheckFleetToken(t *testing.T) {
	strong := "0123456789abcdef0123456789abcdef"
	cases := []struct {
		name  string
		hub   bool
		url   string
		token string
		ok    bool
	}{
		{"no fleet no token", false, "", "", true},
		{"no fleet weak token", false, "", "abc", true},
		{"hub empty", true, "", "", false},
		{"hub readme value", true, "", "a-long-random-value", false},
		{"hub placeholder upper", true, "", " CHANGE-ME ", false},
		{"hub short", true, "", strong[:31], false},
		{"hub strong", true, "", strong, true},
		{"member empty", false, "http://hub:8090", "", false},
		{"member readme value", false, "http://hub:8090", "a-long-random-value", false},
		{"member short", false, "http://127.0.0.1:8090", strong[:20], false},
		{"member strong", false, "http://hub:8090", strong, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Config{FleetHub: tc.hub, FleetURL: tc.url, FleetToken: tc.token}.CheckFleetToken()
			if tc.ok && err != nil {
				t.Fatalf("want ok, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("want error, got ok")
			}
		})
	}
}
