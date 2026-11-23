package dpkgdb

import (
	"strings"
	"testing"
)

// QA 2026-11-20: a Status that is not three words is read as installed; the
// opposite is a package silently missing.
func TestParse_AnOddStatusIsInstalled(t *testing.T) {
	nl := string(rune(10))
	for status, want := range map[string]int{"install ok installed": 1, "installed": 1, "install ok installed extra": 1, "deinstall ok config-files": 0} {
		got, err := Parse(strings.NewReader("Package: x"+nl+"Status: "+status+nl+"Version: 1"+nl+"Architecture: all"+nl+nl), "Debian:12")
		if err != nil || len(got) != want {
			t.Errorf("%q: %d packages, %v; want %d", status, len(got), err, want)
		}
	}
}
