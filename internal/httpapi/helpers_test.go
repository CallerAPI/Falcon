package httpapi

import "os"

func writeFileMode(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}
