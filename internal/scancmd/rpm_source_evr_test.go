package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// a4DB holds source-keyed records -- the shape of Rocky's OSV and Fedora's
// Bodhi feeds, where the source-name lookup is the only path -- each fixed
// at the given EVR.
func a4DB(t *testing.T, fixed map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"httpd", "perl", "nodejs"} {
		v, ok := fixed[name]
		if !ok {
			continue
		}
		if err := w.Put(advisory.Advisory{
			ID: "RLSA-A4-" + name, Kind: advisory.KindVulnerability, Database: "RLSA",
			Severity: []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			Affected: []advisory.Affected{{Ecosystem: "Red Hat:9", Name: name, Ranges: []advisory.Range{{
				Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: v}},
			}}}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"p": {Ecosystems: []string{"Red Hat:9"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// a4Scan scans an image holding these rpm packages and returns the names of
// the packages with a finding.
func a4Scan(t *testing.T, db, osRelease string, entries []ndbFixtureEntry) []string {
	t.Helper()
	for i := range entries {
		entries[i].pkgidx = uint32(i + 1)
	}
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, map[string]string{
		osReleasePath:                      osRelease,
		"usr/lib/sysimage/rpm/Packages.db": string(buildNDBFixture(t, uint32(len(entries)+1), entries)),
	})
	var out, errOut bytes.Buffer
	Run(context.Background(), db, "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut)
	var r struct {
		Findings []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v\nstderr: %s", err, errOut.String())
	}
	var names []string
	for _, f := range r.Findings {
		if !slices.Contains(names, f.Package.Name) {
			names = append(names, f.Package.Name)
		}
	}
	slices.Sort(names)
	return names
}

// 2026-10-22 audit A4: the image path gave a binary rpm's source lookup the
// BINARY's EVR. Measured on real images (2026-10-27): mod_ssl carries epoch 1
// and its source httpd none, so 1:2.4.62 sorted above every httpd fix and the
// finding vanished; perl's subpackages carry their own versions and epoch 0
// while perl is epoch 4, so 1.80-484 sorted below every perl fix and never
// cleared (92 packages on ubi9/perl-532); npm 1:8.19.3 was compared with
// nodejs fixes. The source lookup now compares the SRPM's version-release,
// with the epoch of the installed package named like the source (the spec's
// main package) -- here httpd, perl and nodejs are all installed.
func TestRun_A4_SourceLookupComparesTheSRPMsEVR(t *testing.T) {
	db := a4DB(t, map[string]string{
		"httpd":  "2.4.63-1.el9",
		"perl":   "4:5.32.1-484.el9_8",
		"nodejs": "1:16.19.1-1.el9_2",
	})
	got := a4Scan(t, db, osReleaseRHEL9, []ndbFixtureEntry{
		{name: "httpd", version: "2.4.62", release: "1.el9", sourcerpm: "httpd-2.4.62-1.el9.src.rpm"},
		{name: "mod_ssl", version: "2.4.62", release: "1.el9", sourcerpm: "httpd-2.4.62-1.el9.src.rpm", epoch: 1},
		{name: "perl", version: "5.32.1", release: "484.el9_8", sourcerpm: "perl-5.32.1-484.el9_8.src.rpm", epoch: 4},
		{name: "perl-B", version: "1.80", release: "484.el9_8", sourcerpm: "perl-5.32.1-484.el9_8.src.rpm"},
		{name: "nodejs", version: "16.19.1", release: "1.el9_2", sourcerpm: "nodejs-16.19.1-1.el9_2.src.rpm", epoch: 1},
		{name: "npm", version: "8.19.3", release: "1.16.19.1.1.el9_2", sourcerpm: "nodejs-16.19.1-1.el9_2.src.rpm", epoch: 1},
	})
	if want := []string{"httpd", "mod_ssl"}; !slices.Equal(got, want) {
		t.Errorf("packages with findings = %v, want %v: mod_ssl through httpd's fix, perl-B and npm clean at their sources' fixed builds", got, want)
	}
}

// Without an installed package named like the source, the epoch is the
// one most common among its siblings built at the SRPM's own
// version-release, which carry the spec's top-level Epoch (on 19 measured
// images this matched the main package's epoch in 338 of 338 SRPMs where
// that package was present). mod_ssl's explicit Epoch: 1 is outvoted by
// httpd-core and httpd-filesystem; perl-IO's own version is skipped and
// perl-interpreter's 4 is taken -- the false positive the measurement found
// on ubi8/nodejs-18 is gone.
func TestRun_A4_WithoutTheSameNamePackageTheSiblingsEpochIsUsed(t *testing.T) {
	db := a4DB(t, map[string]string{"httpd": "2.4.63-1.el9", "perl": "4:5.32.1-484.el9_8"})
	got := a4Scan(t, db, osReleaseRHEL9, []ndbFixtureEntry{
		{name: "httpd-core", version: "2.4.62", release: "1.el9", sourcerpm: "httpd-2.4.62-1.el9.src.rpm"},
		{name: "httpd-filesystem", version: "2.4.62", release: "1.el9", sourcerpm: "httpd-2.4.62-1.el9.src.rpm"},
		{name: "mod_ssl", version: "2.4.62", release: "1.el9", sourcerpm: "httpd-2.4.62-1.el9.src.rpm", epoch: 1},
		{name: "perl-interpreter", version: "5.32.1", release: "484.el9_8", sourcerpm: "perl-5.32.1-484.el9_8.src.rpm", epoch: 4},
		{name: "perl-IO", version: "1.43", release: "484.el9_8", sourcerpm: "perl-5.32.1-484.el9_8.src.rpm"},
	})
	if want := []string{"httpd-core", "httpd-filesystem", "mod_ssl"}; !slices.Equal(got, want) {
		t.Errorf("packages with findings = %v, want %v: mod_ssl found through httpd-core's epoch, perl-IO clean through perl-interpreter's", got, want)
	}
}

// With neither the same-name package nor a sibling at the SRPM's
// version-release installed, nothing on the image states the source's epoch
// and the binary's own is used, as before A4; the version-release still
// comes from the SRPM. A source epoch above the binary's then still reads as
// below the fix: the one residual false positive, pinned.
func TestRun_A4_WithNoMainPackageAndNoSiblingTheBinaryEpochIsUsed(t *testing.T) {
	db := a4DB(t, map[string]string{"perl": "4:5.32.1-484.el9_8"})
	got := a4Scan(t, db, osReleaseRHEL9, []ndbFixtureEntry{
		{name: "perl-IO", version: "1.43", release: "484.el9_8", sourcerpm: "perl-5.32.1-484.el9_8.src.rpm"},
	})
	if want := []string{"perl-IO"}; !slices.Equal(got, want) {
		t.Errorf("packages with findings = %v, want %v (the documented residual)", got, want)
	}
	got = a4Scan(t, db, osReleaseRHEL9, []ndbFixtureEntry{
		{name: "perl-Fake", version: "5.32.1", release: "484.el9_8", sourcerpm: "perl-5.32.1-484.el9_8.src.rpm", epoch: 4},
	})
	if len(got) != 0 {
		t.Errorf("packages with findings = %v, want none: the binary's own epoch and the SRPM's version-release reach the fix", got)
	}
}
