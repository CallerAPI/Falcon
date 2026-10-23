package sipguard

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("FALCON_SHARE", "false")
	os.Exit(m.Run())
}
