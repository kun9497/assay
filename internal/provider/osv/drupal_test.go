package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// TestFetch_DrupalPackagistRecordsFoldToPlainPackagist drives Fetch end to end
// over a served archive, the same way TestFetch_CratesIO does, rather than
// asserting foldPackagistEcosystem's return value in isolation. That
// isolated assertion cannot see the failure this covers: familyMatches
// already prefix-matches "Packagist:https://packages.drupal.org/8" against
// the "Packagist" family, so the Drupal record is ingested either way — a
// test that only checked "was it ingested" would stay green even if the fold
// were deleted and the qualified key were stored verbatim. What breaks
// without the fold is that NormalizeName and EcosystemForPURLType can only
// ever build the plain "Packagist" key, so a stored qualified key is
// unreachable by any real lookup — a silent false negative for every
// drupal/* package, D6/D13's failure mode one level further in.
//
// Deleting the foldPackagistEcosystem call in record.go (reverting to the
// raw ra.Package.Ecosystem) makes this go red: the second record's
// Affected[0].Ecosystem would come back
// "Packagist:https://packages.drupal.org/8" instead of "Packagist".
func TestFetch_DrupalPackagistRecordsFoldToPlainPackagist(t *testing.T) {
	const plainRecord = `{
	  "id": "GHSA-plain-packagist",
	  "modified": "2026-08-18T00:00:00Z",
	  "affected": [{
	    "package": {"name": "monolog/monolog", "ecosystem": "Packagist", "purl": "pkg:composer/monolog/monolog"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
	  }]
	}`
	const drupalRecord = `{
	  "id": "GHSA-drupal-contrib",
	  "modified": "2026-08-18T00:00:00Z",
	  "affected": [{
	    "package": {"name": "drupal/core", "ecosystem": "Packagist:https://packages.drupal.org/8", "purl": "pkg:composer/drupal/core"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "8.9.0"}]}]
	  }]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Packagist/all.zip" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(zipWith(t, map[string]string{
			"GHSA-plain-packagist.json": plainRecord,
			"GHSA-drupal-contrib.json":  drupalRecord,
		}))
	}))
	defer srv.Close()

	p := New([]string{"Packagist"}, srv.URL)

	var got []advisory.Advisory
	_, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ingested %d advisories, want 2 (both the plain and the Drupal-qualified record)", len(got))
	}

	byID := map[string]advisory.Advisory{}
	for _, a := range got {
		byID[a.ID] = a
	}
	plain, ok := byID["GHSA-plain-packagist"]
	if !ok {
		t.Fatal("GHSA-plain-packagist not ingested")
	}
	drupal, ok := byID["GHSA-drupal-contrib"]
	if !ok {
		t.Fatal("GHSA-drupal-contrib not ingested")
	}

	if len(plain.Affected) != 1 || plain.Affected[0].Ecosystem != "Packagist" {
		t.Errorf("plain record Affected = %+v, want one entry keyed Packagist", plain.Affected)
	}
	// The record this test is actually for: a "Packagist:<repository URL>"
	// key must be stored as plain "Packagist", not verbatim.
	if len(drupal.Affected) != 1 || drupal.Affected[0].Ecosystem != "Packagist" {
		t.Errorf("drupal record Affected = %+v, want one entry keyed Packagist (folded from "+
			"Packagist:https://packages.drupal.org/8)", drupal.Affected)
	}
	if len(drupal.Affected) == 1 && drupal.Affected[0].Name != "drupal/core" {
		t.Errorf("drupal record package name = %q, want drupal/core", drupal.Affected[0].Name)
	}
}

// TestFoldPackagistEcosystem is the direct unit test for the branches the
// Fetch-level test above cannot reach on its own: a bare "Packagist:" with no
// repository qualifier, ecosystems the fold must leave untouched, and — the
// negative case that matters most, per record.go's own comment — a distro
// family key, which must NOT be folded the same way. Alpine and Debian carry
// their RELEASE after the colon, and the release is part of the key by
// design (D6); folding it away would merge every release into one bucket.
func TestFoldPackagistEcosystem(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"Packagist:https://packages.drupal.org/8", "Packagist"},
		{"Packagist:https://asset-packagist.org", "Packagist"},
		{"Packagist", "Packagist"},
		// A trailing colon with nothing after it is not a real qualified key;
		// left as written rather than guessed at.
		{"Packagist:", "Packagist:"},
		{"Go", "Go"},
		{"crates.io", "crates.io"},
		// D6: distro release qualifiers must survive untouched. This is the
		// fold's own "do not generalize" rule, pinned by test rather than
		// only by comment.
		{"Alpine:v3.19", "Alpine:v3.19"},
		{"Debian:12", "Debian:12"},
		{"Red Hat:9", "Red Hat:9"},
	} {
		if got := foldPackagistEcosystem(tt.in); got != tt.want {
			t.Errorf("foldPackagistEcosystem(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
