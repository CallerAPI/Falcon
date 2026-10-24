package config

import (
	"fmt"
	"strings"
)

// minSecretLength is the shortest shared secret Falcon accepts where one is required.
const minSecretLength = 32

// placeholderSecrets are secret values shipped in examples and docs.
var placeholderSecrets = map[string]bool{
	"a-long-random-value": true,
	"change-me":           true, "changeme": true, "replace-me": true, "replaceme": true,
	"e2e-token": true, "secret": true, "token": true,
}

// checkSecret reports why value is not fit to be a shared secret, or nil.
func checkSecret(name, value string) error {
	v := strings.TrimSpace(value)
	switch {
	case v == "":
		return fmt.Errorf("%s is empty. Generate one with: openssl rand -hex 32", name)
	case placeholderSecrets[strings.ToLower(v)]:
		return fmt.Errorf("%s is an example placeholder. Generate one with: openssl rand -hex 32", name)
	case len(v) < minSecretLength:
		return fmt.Errorf("%s has %d characters. Use at least %d. Generate one with: openssl rand -hex 32", name, len(v), minSecretLength)
	}
	return nil
}

// CheckFleetToken reports whether FALCON_FLEET_TOKEN is fit for a fleet
// hub or member. It applies on any listen address. A process that is
// neither hub nor member needs no fleet token.
func (c Config) CheckFleetToken() error {
	if !c.FleetHub && strings.TrimSpace(c.FleetURL) == "" {
		return nil
	}
	return checkSecret("FALCON_FLEET_TOKEN", c.FleetToken)
}
