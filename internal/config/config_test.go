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
