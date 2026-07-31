// Package version implements per-ecosystem version ordering.
//
// There is deliberately no shared compareVersions (D9). Debian epochs, RPM
// release ordering, semver pre-release precedence, and PEP 440 all disagree,
// and a single function that tries to serve them is the bug this design avoids.
package version

import (
	"errors"
	"strings"
)

// ErrInvalid marks a version string that cannot be ordered. Callers must treat
// it as "unknown", never as "not vulnerable" — a swallowed error here is a
// missed vulnerability.
var ErrInvalid = errors.New("invalid version")

type Comparer interface {
	// Compare returns -1, 0, or 1. It returns an error wrapping ErrInvalid
	// rather than guessing an ordering for input it cannot parse.
	Compare(a, b string) (int, error)
}

var registry = map[string]Comparer{
	"Go":   SemVer{},
	"npm":  SemVer{},
	"PyPI": PEP440{},
}

func For(ecosystem string) (Comparer, bool) {
	// Distro ecosystems carry their release (D6), so "Alpine:v3.19" cannot be a
	// map key — the map would need one entry per release, forever. The bare
	// "Alpine" must NOT resolve: it is not a key we ever build, and letting it
	// through would make a bug that drops the release look like it worked, every
	// lookup landing in an empty bucket and reporting clean.
	if rel, ok := strings.CutPrefix(ecosystem, "Alpine:"); ok && rel != "" {
		return APK{}, true
	}
	c, ok := registry[ecosystem]
	return c, ok
}
