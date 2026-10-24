package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A release number such as 0.9.23 or v0.9.23, also at the end of a
// sentence. The guards on both sides keep the dotted quads of IP addresses
// out of the match.
var releaseNumber = regexp.MustCompile(`(?:^|[^0-9.])(v?0\.[0-9]+\.[0-9]+)(?:\.?[^0-9.]|\.?$)`)

// Every push to main cuts a release, so a release number written into a doc
// or a build message is out of date the next day. CHANGELOG.md is history
// and keeps its numbers.
func TestDocsHaveNoReleaseNumber(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "bin" || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !checkedForReleaseNumber(name) {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(body), "\n") {
			if m := releaseNumber.FindStringSubmatch(line); m != nil {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s:%d has the release number %s. Use make build or $(make -s version)", rel, i+1, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func checkedForReleaseNumber(name string) bool {
	switch name {
	case "CHANGELOG.md":
		return false
	case "Makefile", "Dockerfile", "Dockerfile.release", ".env.example":
		return true
	}
	switch filepath.Ext(name) {
	case ".md", ".yml", ".yaml", ".sh":
		return true
	}
	return false
}
