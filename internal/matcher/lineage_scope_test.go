package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// The 2026-10-22 external review's #2. D53's `+fipsN`/`+esmN` detector and
// D80's `module+el` detector read the VERSION STRING alone, and nothing
// scoped either to the ecosystem whose convention gives the marker its
// meaning. A Go module at `1.0.0+fips1` (valid semver build metadata) was
// reported "an Ubuntu FIPS build" and skipped with SkipCoverage -- so
// `--fail-on-incomplete=target` did not trip either, and a vulnerable
// package left the scan with exit 0. Each rule now applies only where its
// convention holds: Canonical's to Ubuntu keys, the module marker to the
// ecosystems the RPM comparer serves.

func TestMatch_UbuntuLineageMarkerAppliesOnlyToUbuntuKeys(t *testing.T) {
	adv := advWithRange("GO-2026-9001", "Go", "example.com/lib", "0", "2.0.0", advisory.RangeSemver)
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Go\x00example.com/lib": {adv}}}

	for _, v := range []string{"1.0.0+fips1", "1.0.0+esm1", "1.0.0+Fips1.2"} {
		res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{pkg("example.com/lib", v, "Go")}})
		if err != nil {
			t.Fatalf("%s: Match: %v", v, err)
		}
		if len(res.Skipped) != 0 {
			t.Errorf("%s: skipped %+v, want none -- the Ubuntu lineage rule has no meaning on a Go version", v, res.Skipped)
		}
		if len(res.Findings) != 1 {
			t.Errorf("%s: Findings = %d, want 1 (the version is inside [0, 2.0.0))", v, len(res.Findings))
		}
	}
}

// The control the fix must keep: the same marker on an Ubuntu key is still
// the D53 skip, with its reason intact.
func TestMatch_UbuntuLineageMarkerStillSkipsOnUbuntu(t *testing.T) {
	adv := advWithRange("UBUNTU-CVE-2026-9002", "Ubuntu:22.04:LTS", "openssl", "0", "3.0.2-0ubuntu1.20", advisory.RangeEcosystem)
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Ubuntu:22.04:LTS\x00openssl": {adv}}}

	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{pkg("openssl", "3.0.2-0ubuntu1.15+esm1", "Ubuntu:22.04:LTS")}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %+v, want none: an ESM build is judged against lineage data this database does not hold (D53)", res.Findings)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Cause != SkipCoverage || !strings.Contains(res.Skipped[0].Reason, "Ubuntu ESM build") {
		t.Errorf("Skipped = %+v, want one SkipCoverage naming the Ubuntu ESM build", res.Skipped)
	}
}

func TestMatch_ModuleMarkerAppliesOnlyToRPMEcosystems(t *testing.T) {
	cases := []struct{ eco, name, key, version string }{
		{"Go", "example.com/lib", "Go\x00example.com/lib", "1.0.0-module+el9"},
		{"npm", "left-pad", "npm\x00left-pad", "1.0.0-module+el9.6.0"},
	}
	for _, c := range cases {
		adv := advWithRange("X-2026-9003", c.eco, c.name, "0", "2.0.0", advisory.RangeSemver)
		s := fakeStore{byKey: map[string][]advisory.Advisory{c.key: {adv}}}
		res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{pkg(c.name, c.version, c.eco)}})
		if err != nil {
			t.Fatalf("%s %s: Match: %v", c.eco, c.version, err)
		}
		if len(res.Skipped) != 0 {
			t.Errorf("%s %s: skipped %+v, want none -- a module build is an RPM notion", c.eco, c.version, res.Skipped)
		}
		if len(res.Findings) != 1 {
			t.Errorf("%s %s: Findings = %d, want 1", c.eco, c.version, len(res.Findings))
		}
	}
}

// The control: on an RPM key a module build with no readable stream is
// still D80's skip.
func TestMatch_ModuleMarkerStillSkipsOnRPMKeys(t *testing.T) {
	const eco = "Rocky Linux:9"
	adv := advWithRange("RLSA-2026:9004", eco, "nodejs", "0", "1:20.20.2-2.module+el9.6.0+24220+c44c288d", advisory.RangeEcosystem)
	s := fakeStore{byKey: map[string][]advisory.Advisory{eco + "\x00nodejs": {adv}}}

	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{pkg("nodejs", "1:20.18.1-1.module+el9.5.0+21542+abc12345", eco)}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %+v, want none: a stream-less module build is not judged (D80)", res.Findings)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Cause != SkipCoverage || !strings.Contains(res.Skipped[0].Reason, "modular RPM build") {
		t.Errorf("Skipped = %+v, want one SkipCoverage naming the modular RPM build", res.Skipped)
	}
}
