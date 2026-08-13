package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// TestFetch_CratesIO drives the fetch end to end over a served archive rather
// than asserting that the Ecosystems list contains a string (D62).
//
// The list assertion cannot see the failure this covers. A crates.io archive is
// fetched under the key "crates.io", and familyMatches compares that key to the
// one inside each record — so a mismatch there ingests zero records while the
// list still names the ecosystem, the fetch still succeeds, and the only
// symptom is that every Rust package reports its ecosystem as absent from the
// database. That is a loud skip rather than a false clean, which is exactly why
// nothing else in the package would go red.
//
// It passes the ecosystem explicitly, so removing crates.io from the Ecosystems
// list does NOT fail this test — verified, not assumed. That is the division of
// labour rather than a gap: this covers whether the machinery handles the key,
// and TestEcosystems_IncludesUbuntu covers whether anything asks it to. A single
// test doing both would still pass if either half broke in the right way.
func TestFetch_CratesIO(t *testing.T) {
	// Shaped after a real record: RUSTSEC authors it, GHSA aliases it, the
	// range is SEMVER, and the purl type (cargo) is not the ecosystem key
	// (crates.io).
	const rec = `{
	  "id": "RUSTSEC-2020-0071",
	  "aliases": ["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"],
	  "modified": "2026-08-01T00:00:00Z",
	  "affected": [{
	    "package": {"name": "time", "ecosystem": "crates.io", "purl": "pkg:cargo/time"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.2.7"}, {"fixed": "0.2.23"}]}]
	  }],
	  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H"}]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/crates.io/all.zip" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(zipWith(t, map[string]string{"RUSTSEC-2020-0071.json": rec}))
	}))
	defer srv.Close()

	p := New([]string{"crates.io"}, srv.URL)

	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ingested %v, want the one crates.io record", got)
	}
	a := got[0]
	if a.ID != "RUSTSEC-2020-0071" {
		t.Errorf("ID = %q, want RUSTSEC-2020-0071", a.ID)
	}
	// The ecosystem the advisory is STORED under decides which bucket a Rust
	// package's lookup lands in. "cargo" here would key it to a bucket nothing
	// ever reads, and the package would report clean.
	if len(a.Affected) != 1 || a.Affected[0].Ecosystem != "crates.io" {
		t.Fatalf("Affected = %+v, want one entry keyed crates.io", a.Affected)
	}
	if a.Affected[0].Name != "time" {
		t.Errorf("package = %q, want time", a.Affected[0].Name)
	}
	if len(prov.Ecosystems) != 1 || prov.Ecosystems[0] != "crates.io" {
		t.Errorf("Provenance.Ecosystems = %v, want [crates.io]", prov.Ecosystems)
	}
}
