package pnpmlock

import "testing"

// QA 2026-11-20. An ordinary release served by a mirror was refused as a git
// or foreign tarball, so --fail-on never saw it.
func TestParse_ARegistryReleaseServedByAMirrorIsCataloged(t *testing.T) {
	nl := string(rune(0x0a))
	for _, tc := range []struct {
		name, lock, key, res string
		want                 bool
	}{
		{"v9 mirror", "9.0", "lodash@4.17.20", "{integrity: sha512-x, tarball: https://npm.corp.example/lodash/-/lodash-4.17.20.tgz}", true},
		{"v9 scoped, non-standard path", "9.0", "'@acme/ui@1.2.3-rc.1'", "{integrity: sha512-x, tarball: https://npm.pkg.github.com/download/@acme/ui/1.2.3-rc.1/abc}", true},
		{"v5 mirror", "5.4", "/lodash/4.17.20", "{integrity: sha512-x, tarball: https://npm.corp.example/lodash.tgz}", true},
		{"no integrity", "9.0", "lodash@4.17.20", "{tarball: https://npm.corp.example/lodash/-/lodash-4.17.20.tgz}", false},
		{"github archive", "9.0", "lodash@4.17.20", "{integrity: sha512-x, tarball: https://codeload.github.com/lodash/lodash/tar.gz/abc}", false},
		{"url dependency", "9.0", "'x@https://host.example/y@1.2.3'", "{integrity: sha512-x, tarball: https://host.example/y.tgz}", false},
		{"v5 url dependency", "5.4", "'@host.example/some/path/1.2.3'", "{integrity: sha512-x, tarball: https://host.example/some/path/1.2.3}", false},
		{"unscoped path", "5.4", "host.example/path/1.2.3", "{integrity: sha512-x, tarball: https://host.example/path/1.2.3}", false},
		{"local tarball", "9.0", "'x@file:y@1.2.3'", "{integrity: sha512-x, tarball: 'file:y.tgz'}", false},
		{"commit version", "9.0", "x@0abc123", "{integrity: sha512-x, tarball: https://host.example/x.tgz}", false},
	} {
		path := write(t, "lockfileVersion: '"+tc.lock+"'"+nl+nl+"packages:"+nl+nl+"  "+tc.key+":"+nl+"    resolution: "+tc.res+nl)
		pkgs, _, skipped, err := counts(path)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := pkgs == 1; got != tc.want || pkgs+skipped != 1 {
			t.Errorf("%s: %d cataloged, %d skipped; want cataloged = %v", tc.name, pkgs, skipped, tc.want)
		}
	}
}

func counts(path string) (int, int, int, error) {
	pkgs, stats, skipped, err := Parse(path)
	return len(pkgs), stats.Components, len(skipped), err
}
