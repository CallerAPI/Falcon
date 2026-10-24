package config

import "testing"

func TestCarrierProfileDefaults(t *testing.T) {
	t.Setenv("FALCON_PROFILE", "carrier")
	c := Load()
	if c.Profile != ProfileCarrier {
		t.Fatalf("profile = %q", c.Profile)
	}
	if c.ChallengeScore != 101 || c.RejectScore != 101 {
		t.Fatalf("carrier thresholds = %d/%d, want 101/101", c.ChallengeScore, c.RejectScore)
	}
	if c.VelocityIP != 0 || c.VelocityFrom != 0 || c.VelocityScan != 0 {
		t.Fatalf("carrier velocity = %d/%d/%d, want all off", c.VelocityIP, c.VelocityFrom, c.VelocityScan)
	}
	if c.FlagScore != 40 {
		t.Fatalf("flag stays %d", c.FlagScore)
	}
}

func TestExplicitVariableBeatsProfile(t *testing.T) {
	t.Setenv("FALCON_PROFILE", "carrier")
	t.Setenv("FALCON_REJECT_SCORE", "95")
	t.Setenv("FALCON_VELOCITY_IP", "500")
	c := Load()
	if c.RejectScore != 95 || c.VelocityIP != 500 || c.ChallengeScore != 101 {
		t.Fatalf("override: reject=%d ip=%d challenge=%d", c.RejectScore, c.VelocityIP, c.ChallengeScore)
	}
}

func TestTrunkIsTheDefaultProfile(t *testing.T) {
	t.Setenv("FALCON_PROFILE", "")
	c := Load()
	if c.Profile != ProfileTrunk || c.ChallengeScore != 60 || c.RejectScore != 80 || c.VelocityIP != 30 {
		t.Fatalf("trunk defaults: %+v", c)
	}
}

func TestCheckToken(t *testing.T) {
	strong := "0123456789abcdef0123456789abcdef"
	cases := []struct {
		name   string
		listen string
		token  string
		open   bool
		ok     bool
	}{
		{"loopback empty", "127.0.0.1:8090", "", false, true},
		{"loopback placeholder", "127.0.0.1:8090", "change-me", false, true},
		{"localhost short", "localhost:8090", "abc", false, true},
		{"ipv6 loopback short", "[::1]:8090", "abc", false, true},
		{"public empty", "0.0.0.0:8090", "", false, false},
		{"public empty allow open", "0.0.0.0:8090", "", true, true},
		{"public placeholder", "0.0.0.0:8090", "change-me", false, false},
		{"public placeholder upper", "0.0.0.0:8090", " CHANGE-ME ", false, false},
		{"public placeholder allow open", "0.0.0.0:8090", "replace-me", true, false},
		{"public short", "10.0.0.5:8090", strong[:31], false, false},
		{"public strong", "0.0.0.0:8090", strong, false, true},
		{"all interfaces no host", ":8090", strong[:20], false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Config{Listen: tc.listen, Token: tc.token, AllowOpen: tc.open}.CheckToken()
			if tc.ok && err != nil {
				t.Fatalf("want ok, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("want error, got ok")
			}
		})
	}
}
