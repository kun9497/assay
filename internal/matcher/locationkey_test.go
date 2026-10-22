package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// Two installs of one package that differ only in where the lockfile put
// them -- lodash under node_modules/lodash and the same version under an
// alias directory -- are two findings, and their order must not depend on
// input order surviving. Location.Install is part of the key for the same
// reason LayerDigest is.
func TestLocationKey_DistinguishesInstallPaths(t *testing.T) {
	a := pkgmeta.Package{Locations: []pkgmeta.Location{{Path: "package-lock.json"}}}
	b := pkgmeta.Package{Locations: []pkgmeta.Location{{Path: "package-lock.json", Install: "node_modules/utility-alias"}}}
	if locationKey(a) == locationKey(b) {
		t.Fatalf("locationKey ignores Install: %q", locationKey(a))
	}
}
