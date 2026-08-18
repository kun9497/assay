package dirscan

// Written before composerlock exists, and driving Parse rather than the
// parser: delete the KindComposerLock arm and every test below must go red,
// because the manifest falls through to default and becomes an Unread.

import "testing"

const composerLock = `{
  "packages": [
    {"name": "vendor-fixture/monolog-fixture", "version": "v2.9.1"}
  ],
  "packages-dev": [
    {"name": "vendor-fixture/phpunit-fixture", "version": "9.6.3"},
    {"name": "vendor-fixture/branch-fixture", "version": "dev-main"}
  ]
}
`

func TestParse_ComposerLockReachesTheDispatch(t *testing.T) {
	root := writeTree(t, map[string]string{"composer.lock": composerLock})

	version, location := findPackage(t, root, "vendor-fixture/monolog-fixture")
	if version != "v2.9.1" {
		t.Errorf("monolog-fixture version = %q, want v2.9.1", version)
	}
	if location != "composer.lock" {
		t.Errorf("location = %q, want composer.lock", location)
	}
}

// packages-dev installs in CI too - same reasoning as Pipfile's develop
// section - so a dev-only package must still be cataloged.
func TestParse_ComposerLockDevPackagesAreIncluded(t *testing.T) {
	root := writeTree(t, map[string]string{"composer.lock": composerLock})

	if version, _ := findPackage(t, root, "vendor-fixture/phpunit-fixture"); version != "9.6.3" {
		t.Errorf("phpunit-fixture version = %q, want 9.6.3", version)
	}
}

// A "dev-*" version is a branch alias, not a released version: there is
// nothing here for a comparer to order. Counted, not dropped.
func TestParse_ComposerLockDevBranchVersionIsCountedAndSkipped(t *testing.T) {
	root := writeTree(t, map[string]string{"composer.lock": composerLock})

	target, stats, found, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, u := range found.Unread {
		t.Errorf("unexpected unread manifest %s: %s", u.Path, u.Reason)
	}
	for _, p := range target.Packages {
		if p.Name == "vendor-fixture/branch-fixture" {
			t.Errorf("branch-fixture was cataloged as %+v; a dev-* version names "+
				"no released package", p)
		}
	}
	// monolog-fixture and phpunit-fixture are cataloged; branch-fixture is
	// counted and skipped: 3 components, 2 cataloged, 1 skipped.
	if stats.Components != 3 || stats.Cataloged != 2 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want 3 components, 2 cataloged, 1 skipped", stats)
	}
}

// The Packagist Comparer normalizes the "v" prefix (D9) - stripping it here
// would be a second, competing definition of that rule.
func TestParse_ComposerLockVersionKeptVerbatim(t *testing.T) {
	root := writeTree(t, map[string]string{"composer.lock": composerLock})

	target, _, _, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var checked bool
	for _, p := range target.Packages {
		if p.Name != "vendor-fixture/monolog-fixture" {
			continue
		}
		checked = true
		if p.Version != "v2.9.1" {
			t.Errorf("Version = %q, want v2.9.1 (verbatim, \"v\" prefix kept)", p.Version)
		}
		if p.Type != "composer" {
			t.Errorf("Type = %q, want composer", p.Type)
		}
		if p.Ecosystem != "Packagist" {
			t.Errorf("Ecosystem = %q, want Packagist", p.Ecosystem)
		}
		if p.PURL != "pkg:composer/vendor-fixture/monolog-fixture@v2.9.1" {
			t.Errorf("PURL = %q, want pkg:composer/vendor-fixture/monolog-fixture@v2.9.1", p.PURL)
		}
	}
	if !checked {
		t.Fatal("vendor-fixture/monolog-fixture was not found among the cataloged packages")
	}
}
