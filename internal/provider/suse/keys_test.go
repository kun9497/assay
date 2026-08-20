package suse

import (
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/version"
)

// TestKeyAgreesWithCataloger is the byte-for-byte cross-check the D77
// design calls "THE silent-miss point of the whole slice": distro.go
// (internal/pkgmeta) derives a SLES or openSUSE Leap key from
// /etc/os-release fields, this package derives one from a CSAF product
// name, and the two are computed by completely independent code reading
// completely different inputs. A key MISMATCH is silent -- both sides still
// produce a plausible-looking string, and only a scan finding nothing
// stored under it would ever reveal the drift, which looks identical to a
// clean image (D20 exists for this exact failure one layer up).
//
// Each case below builds a pkgmeta.Distro the way a real image's os-release
// would (VERSION_ID values verified live: 15.6 against a pulled
// registry.suse.com/bci/bci-base:15.6, opensuse-leap 15.6 against a pulled
// docker.io/opensuse/leap:15.6) and asserts three things together: the
// cataloger resolves an ecosystem at all, that ecosystem equals what
// foldKey produces from the CSAF product name a real image of that release
// carries, and version.For recognizes the resulting key (so the matcher
// actually has a comparer to evaluate a package against, not just a key
// that superficially matches).
func TestKeyAgreesWithCataloger(t *testing.T) {
	for _, tc := range []struct {
		name        string
		distro      pkgmeta.Distro
		csafProduct string // the platform product name the live feed carries for this release
	}{
		{
			"SLES 15 SP6, verified against a pulled bci-base:15.6 image",
			pkgmeta.Distro{ID: "sles", VersionID: "15.6", PrettyName: "SUSE Linux Enterprise Server 15 SP6"},
			"SUSE Linux Enterprise Server 15 SP6",
		},
		{
			"SLES 15 SP6's own module product folds to the identical key",
			pkgmeta.Distro{ID: "sles", VersionID: "15.6"},
			"SUSE Linux Enterprise Module for Basesystem 15 SP6",
		},
		{
			"SLES 15 GA (pre-SP1), the bare product with no SP suffix",
			pkgmeta.Distro{ID: "sles", VersionID: "15.0"},
			"SUSE Linux Enterprise Server 15",
		},
		{
			"SLES 12 SP5",
			pkgmeta.Distro{ID: "sles", VersionID: "12.5"},
			"SUSE Linux Enterprise Server 12 SP5",
		},
		{
			"SLES 16.0, the dotted line that carries no SP wording",
			pkgmeta.Distro{ID: "sles", VersionID: "16.0"},
			"SUSE Linux Enterprise Server 16.0",
		},
		{
			"openSUSE Leap 15.6, verified against a pulled opensuse/leap:15.6 image",
			pkgmeta.Distro{ID: "opensuse-leap", VersionID: "15.6"},
			"openSUSE Leap 15.6",
		},
		{
			"openSUSE Leap 16.0",
			pkgmeta.Distro{ID: "opensuse-leap", VersionID: "16.0"},
			"openSUSE Leap 16.0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalogerKey, err := tc.distro.Ecosystem()
			if err != nil {
				t.Fatalf("pkgmeta.Distro.Ecosystem() = %v, want a resolved key", err)
			}
			providerKey, ok := foldKey(tc.csafProduct)
			if !ok {
				t.Fatalf("foldKey(%q) refused to fold a real, live CSAF product name", tc.csafProduct)
			}
			if catalogerKey != providerKey {
				t.Errorf("cataloger key %q != provider key %q -- a SCAN of this release would look "+
					"up one string and the DATABASE would hold the other, reporting clean with no "+
					"error at all", catalogerKey, providerKey)
			}
			if _, ok := version.For(catalogerKey); !ok {
				t.Errorf("version.For(%q) has no comparer -- the matcher could never evaluate a "+
					"package under this key even if the lookup found something", catalogerKey)
			}
		})
	}
}

// TestKeyAgreesWithCataloger_TumbleweedNeverResolves pins the refusal on
// both sides at once: the cataloger refuses opensuse-tumbleweed by ID
// (distro_test.go covers this directly), and the provider refuses
// "openSUSE Tumbleweed" by name (csaf_test.go's TestFoldKey covers this
// directly) -- this test is what proves neither refusal was quietly
// dropped in a way the OTHER side's test could not see, since each test
// file only imports its own package's logic.
func TestKeyAgreesWithCataloger_TumbleweedNeverResolves(t *testing.T) {
	if _, err := (pkgmeta.Distro{ID: "opensuse-tumbleweed", VersionID: "20260818"}).Ecosystem(); err == nil {
		t.Error("the cataloger resolved a key for Tumbleweed")
	}
	if _, ok := foldKey(tumbleweedName); ok {
		t.Error("the provider folded a key for Tumbleweed")
	}
}
