package dirscan

// Written before gemlock exists, and driving Parse rather than the parser:
// the recurring defect this repo keeps hitting is a cataloger with an
// exhaustive test of its own that nothing ever calls. Delete the
// KindGemfileLock arm and every test below must go red, because the manifest
// falls through to default and becomes an Unread.

import "testing"

// gemfileLock is shaped after a real Gemfile.lock: a GEM section whose specs
// list two real gems (one with a dependency constraint line underneath it),
// followed by a GIT section resolving a forked gem. "shared-dep-fixture"
// appears ONLY as a 6-space dependency constraint under rails-fixture and
// never has a spec entry of its own - its absence from the catalog is what
// proves the 6-space line was not turned into a package, since asserting
// rails-fixture and actionpack-fixture alone would still pass if their OWN
// 6-space constraint lines were double-counted under names that already
// exist elsewhere.
const gemfileLock = `GEM
  remote: https://rubygems.org/
  specs:
    actionpack-fixture (7.0.4)
      shared-dep-fixture (= 7.0.4)
    rails-fixture (7.0.4)
      actionpack-fixture (= 7.0.4)
      shared-dep-fixture (= 7.0.4)

GIT
  remote: https://example.invalid/forked-gem-fixture.git
  revision: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  specs:
    forked-gem-fixture (2.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  rails-fixture
  forked-gem-fixture!

BUNDLED WITH
   2.3.7
`

func TestParse_GemfileLockReachesTheDispatch(t *testing.T) {
	root := writeTree(t, map[string]string{"Gemfile.lock": gemfileLock})

	version, location := findPackage(t, root, "rails-fixture")
	if version != "7.0.4" {
		t.Errorf("rails-fixture version = %q, want 7.0.4", version)
	}
	if location != "Gemfile.lock" {
		t.Errorf("location = %q, want Gemfile.lock", location)
	}
	if version, _ := findPackage(t, root, "actionpack-fixture"); version != "7.0.4" {
		t.Errorf("actionpack-fixture version = %q, want 7.0.4", version)
	}
}

// The distinguishing case: a name that appears ONLY at 6 spaces, as a
// dependency constraint, must never become a package in its own right.
func TestParse_GemfileLockSixSpaceConstraintIsNotAPackage(t *testing.T) {
	root := writeTree(t, map[string]string{"Gemfile.lock": gemfileLock})

	target, _, _, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, p := range target.Packages {
		if p.Name == "shared-dep-fixture" {
			t.Errorf("shared-dep-fixture was cataloged as %+v; it only ever "+
				"appears as a 6-space dependency constraint, never a 4-space spec", p)
		}
	}
}

// GIT specs resolve a real gem, but not from rubygems.org - a fork's version
// number carries no promise it matches the upstream advisory data this scan
// compares against. Counted, not dropped.
func TestParse_GemfileLockGitSpecIsCountedAndSkipped(t *testing.T) {
	root := writeTree(t, map[string]string{"Gemfile.lock": gemfileLock})

	target, stats, found, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, u := range found.Unread {
		t.Errorf("unexpected unread manifest %s: %s", u.Path, u.Reason)
	}
	for _, p := range target.Packages {
		if p.Name == "forked-gem-fixture" {
			t.Errorf("forked-gem-fixture was cataloged as %+v; a GIT spec must "+
				"be counted and skipped, not turned into a package", p)
		}
	}
	// Two GEM specs (actionpack-fixture, rails-fixture) are cataloged; the one
	// GIT spec (forked-gem-fixture) is counted and skipped. The 6-space
	// dependency constraint lines contribute nothing to either count.
	if stats.Components != 3 || stats.Cataloged != 2 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want 3 components, 2 cataloged, 1 skipped", stats)
	}
}

func TestParse_GemfileLockEcosystemAndPURL(t *testing.T) {
	root := writeTree(t, map[string]string{"Gemfile.lock": gemfileLock})

	target, _, _, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var checked bool
	for _, p := range target.Packages {
		if p.Name != "rails-fixture" {
			continue
		}
		checked = true
		if p.Type != "gem" {
			t.Errorf("Type = %q, want gem", p.Type)
		}
		if p.Ecosystem != "RubyGems" {
			t.Errorf("Ecosystem = %q, want RubyGems", p.Ecosystem)
		}
		if p.PURL != "pkg:gem/rails-fixture@7.0.4" {
			t.Errorf("PURL = %q, want pkg:gem/rails-fixture@7.0.4", p.PURL)
		}
	}
	if !checked {
		t.Fatal("rails-fixture was not found among the cataloged packages")
	}
}
