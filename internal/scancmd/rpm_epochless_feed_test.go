package scancmd

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// epochlessDB holds one record per entry, fixed at the given version under
// every name listed, in the shape of the two feeds that carry no usable epoch:
// Photon's flat JSON writes none at all, and Azure Linux's OVAL writes `0:` on
// every fix (measured 2026-10-27 on the published database: 14,421 Azure
// fixes all at `0:`, over 200,000 Photon fixes with no epoch).
func epochlessDB(t *testing.T, eco string, records map[string][]string, fixed string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for id, names := range records {
		var aff []advisory.Affected
		for _, n := range names {
			aff = append(aff, advisory.Affected{Ecosystem: eco, Name: n, Ranges: []advisory.Range{{
				Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}},
			}}})
		}
		if err := w.Put(advisory.Advisory{
			ID: id, Kind: advisory.KindVulnerability, Database: "EPOCHLESS",
			Severity: []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			Affected: aff,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"p": {Ecosystems: []string{eco}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// D153 on Photon, through Run. Photon 5.0's nginx spec carries Epoch: 1, and
// the feed names six of its subpackages under their own names
// (nginx-mod-njs among them) in the same advisories as nginx itself, with no
// epoch on any fix. nginx-mod-njs's own-name lookup compares 1:1.25.5 with
// 1.25.5 and misses; only the source lookup, with the epoch D153 drops on
// Photon keys, reaches the fix. So this holds three things at once: the call
// site, the epochless rule for "Photon OS:", and the matcher not marking an
// advisory seen on a miss under the first name it tried.
func TestRun_D153_PhotonEpochSubpackageFoundThroughItsSource(t *testing.T) {
	db := epochlessDB(t, "Photon OS:5", map[string][]string{
		"PHSA-D153-0001": {"nginx", "nginx-mod-njs"},
	}, "1.25.5-2.ph5")
	pkgs := func(release string) []ndbFixtureEntry {
		srpm := "nginx-1.25.5-" + release + ".src.rpm"
		return []ndbFixtureEntry{
			{name: "nginx", version: "1.25.5", release: release, sourcerpm: srpm, epoch: 1},
			{name: "nginx-mod-njs", version: "1.25.5", release: release, sourcerpm: srpm, epoch: 1},
		}
	}
	if got, want := a4Scan(t, db, osReleasePhoton5, pkgs("1.ph5")), []string{"nginx", "nginx-mod-njs"}; !slices.Equal(got, want) {
		t.Errorf("below the fix: packages with findings = %v, want %v -- the epoch must not reach the source version on a Photon key", got, want)
	}
	if got := a4Scan(t, db, osReleasePhoton5, pkgs("2.ph5")); len(got) != 0 {
		t.Errorf("at the fixed build: packages with findings = %v, want none", got)
	}
}

// D153 on Azure Linux, through Run. The feed names source packages only, all
// fixed at `0:`, while ca-certificates' subpackages carry Epoch 1 on real
// azurelinux/base/core:3.0 and cbl-mariner/base/core:2.0 images. With no
// same-name package installed, the source version would otherwise take
// the siblings' epoch (D153 step 2) and sort above every fix.
func TestRun_D153_AzureLinuxEpochSubpackageFoundThroughItsSource(t *testing.T) {
	for _, c := range []struct{ label, osRelease, eco, dist string }{
		{"azurelinux 3.0", osReleaseAzureLinux3, "Azure Linux:3", "azl3"},
		{"mariner 2.0", osReleaseMariner2, "Azure Linux:2", "cm2"},
	} {
		t.Run(c.label, func(t *testing.T) {
			db := epochlessDB(t, c.eco, map[string][]string{
				"CVE-D153-0002": {"ca-certificates"},
			}, "0:3.0.0-7."+c.dist)
			pkgs := func(release string) []ndbFixtureEntry {
				srpm := "ca-certificates-3.0.0-" + release + ".src.rpm"
				return []ndbFixtureEntry{
					{name: "ca-certificates-base", version: "3.0.0", release: release, sourcerpm: srpm, epoch: 1},
					{name: "ca-certificates-shared", version: "3.0.0", release: release, sourcerpm: srpm, epoch: 1},
				}
			}
			if got, want := a4Scan(t, db, c.osRelease, pkgs("6."+c.dist)), []string{"ca-certificates-base", "ca-certificates-shared"}; !slices.Equal(got, want) {
				t.Errorf("below the fix: packages with findings = %v, want %v", got, want)
			}
			if got := a4Scan(t, db, c.osRelease, pkgs("7."+c.dist)); len(got) != 0 {
				t.Errorf("at the fixed build: packages with findings = %v, want none", got)
			}
		})
	}
}
