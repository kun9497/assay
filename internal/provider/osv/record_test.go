package osv

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

const goRecord = `{
  "schema_version": "1.7.3",
  "id": "GHSA-227x-7mh8-3cf6",
  "modified": "2025-10-23T20:12:12Z",
  "aliases": ["CVE-2025-59823", "GO-2025-3981"],
  "summary": "Code injection in Gardener provider extensions",
  "affected": [
    {
      "package": {"name": "github.com/gardener/a", "ecosystem": "Go"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.64.0"}]}]
    },
    {
      "package": {"name": "github.com/gardener/b", "ecosystem": "Go"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.46.0"}]}]
    }
  ],
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]
}`

func TestConvert_Go(t *testing.T) {
	got, ok, err := Convert([]byte(goRecord), "Go")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if !ok {
		t.Fatal("Convert returned ok=false, want a converted advisory")
	}
	if got.ID != "GHSA-227x-7mh8-3cf6" {
		t.Errorf("ID = %q", got.ID)
	}
	if got.Source != "osv" {
		t.Errorf("Source = %q, want osv", got.Source)
	}
	if got.Kind != advisory.KindVulnerability {
		t.Errorf("Kind = %q, want vulnerability", got.Kind)
	}
	if len(got.Affected) != 2 {
		t.Fatalf("Affected = %d entries, want 2", len(got.Affected))
	}
	if got.Affected[0].Ranges[0].Events[0].Introduced != "0" {
		t.Error("the introduced sentinel must survive conversion verbatim")
	}
	if len(got.Severity) != 1 || got.Severity[0].Type != "CVSS_V3" {
		t.Errorf("Severity = %+v, want one CVSS_V3 vector", got.Severity)
	}
	// Both alias fields feed the KISA join (D3); this record uses aliases.
	if len(got.Aliases) != 2 {
		t.Errorf("Aliases = %v, want 2", got.Aliases)
	}
}

func TestConvert_UpstreamFieldIsCarried(t *testing.T) {
	// OSV 1.7 puts the CVE link in `upstream`. A record can have upstream and
	// no aliases at all; reading only one field makes the KISA join fail
	// silently (D3).
	const rec = `{
	  "id": "ALPINE-CVE-2006-20001",
	  "upstream": ["CVE-2006-20001"],
	  "affected": [{"package": {"name": "apache2", "ecosystem": "Alpine:v3.19"},
	                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.4.55-r0"}]}]}]
	}`
	got, ok, err := Convert([]byte(rec), "Alpine:v3.19")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Upstream) != 1 || got.Upstream[0] != "CVE-2006-20001" {
		t.Errorf("Upstream = %v, want [CVE-2006-20001]", got.Upstream)
	}
	if len(got.Aliases) != 0 {
		t.Errorf("Aliases = %v, want empty", got.Aliases)
	}
}

func TestConvert_DropsWithdrawn(t *testing.T) {
	const rec = `{
	  "id": "GHSA-withdrawn",
	  "withdrawn": "2024-01-01T00:00:00Z",
	  "affected": [{"package": {"name": "x", "ecosystem": "Go"},
	                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
	}`
	_, ok, err := Convert([]byte(rec), "Go")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if ok {
		t.Error("withdrawn record was converted; it must be dropped (D16)")
	}
}

func TestConvert_DropsMalicious(t *testing.T) {
	const rec = `{
	  "id": "MAL-2021-1",
	  "summary": "Malicious code in cxp-jquery (npm)",
	  "affected": [{"package": {"name": "cxp-jquery", "ecosystem": "npm"},
	                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
	}`
	_, ok, err := Convert([]byte(rec), "npm")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if ok {
		t.Error("MAL record was converted; it must be dropped in slice 1 (D15)")
	}
}

func TestConvert_KeepsForeignEcosystemEntries(t *testing.T) {
	// Fetch emits one advisory per ecosystem it covers and Put overwrites by ID,
	// so stripping foreign entries here left the last pass's record holding only
	// its own ecosystem while the earlier ecosystem's index still pointed at it.
	// The matcher then discarded every entry: no hit, no skip, no error. Measured
	// on the live Go dump, 15 of 8,497 records were clobbered this way.
	const rec = `{
	  "id": "GHSA-mixed",
	  "affected": [
	    {"package": {"name": "github.com/protocolbuffers/protobuf", "ecosystem": "Go"},
	     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]},
	    {"package": {"name": "protobuf", "ecosystem": "PyPI"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.18.3"}]}]}
	  ]
	}`
	for _, want := range []string{"Go", "PyPI"} {
		got, ok, err := Convert([]byte(rec), want)
		if err != nil || !ok {
			t.Fatalf("Convert(_, %q): ok=%v err=%v", want, ok, err)
		}
		if len(got.Affected) != 2 {
			t.Errorf("Convert(_, %q) kept %d affected entries, want both: a later pass "+
				"would otherwise overwrite the record and orphan the other index",
				want, len(got.Affected))
		}
	}

	// A record naming neither ingested ecosystem is still dropped.
	if _, ok, err := Convert([]byte(rec), "crates.io"); err != nil || ok {
		t.Errorf("Convert(_, crates.io) = ok %v err %v, want dropped", ok, err)
	}
}

func TestConvert_DropsGitRanges(t *testing.T) {
	const rec = `{
	  "id": "PYSEC-git",
	  "affected": [{"package": {"name": "django", "ecosystem": "PyPI"},
	    "ranges": [
	      {"type": "GIT", "repo": "https://github.com/django/django",
	       "events": [{"introduced": "9305c0e12d43c4df999c3301a1f0c742264a657e"}]},
	      {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.1"}]}
	    ]}]
	}`
	got, ok, err := Convert([]byte(rec), "PyPI")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	rs := got.Affected[0].Ranges
	if len(rs) != 1 || rs[0].Type != advisory.RangeEcosystem {
		t.Errorf("Ranges = %+v, want only the ECOSYSTEM range", rs)
	}
}

func TestConvert_KeepsNonCanonicalEndpointsVerbatim(t *testing.T) {
	// OSV publishes non-normalized PyPI endpoints. Normalizing here would be
	// lossy (D13); the comparer handles it.
	const rec = `{
	  "id": "PYSEC-noncanon",
	  "affected": [{"package": {"name": "django", "ecosystem": "PyPI"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.8c1"}]}],
	    "versions": ["1.5c1", "4.0.0.beta1"]}]
	}`
	got, _, err := Convert([]byte(rec), "PyPI")
	if err != nil {
		t.Fatal(err)
	}
	if f := got.Affected[0].Ranges[0].Events[1].Fixed; f != "1.8c1" {
		t.Errorf("fixed = %q, want the verbatim 1.8c1", f)
	}
	if got.Affected[0].Versions[1] != "4.0.0.beta1" {
		t.Errorf("versions = %v, want verbatim", got.Affected[0].Versions)
	}
}

func TestConvert_DropsGitOnlyAffected(t *testing.T) {
	// An in-ecosystem entry whose only ranges are GIT, with no enumerated
	// versions, has nothing a version comparer could act on. Dropping it is
	// correct — a commit SHA cannot be matched against a package version —
	// but the path is distinct from the foreign-ecosystem drop and needs its
	// own coverage. Measured across live data this is rare (2 of 12,524 PyPI
	// records, 0 of 8,492 Go), and both are OSS-Fuzz records that are
	// commit-scoped by nature.
	const rec = `{
	  "id": "OSV-2021-449",
	  "affected": [{"package": {"name": "django", "ecosystem": "PyPI"},
	    "ranges": [{"type": "GIT", "repo": "https://github.com/django/django",
	                "events": [{"introduced": "9305c0e12d43c4df999c3301a1f0c742264a657e"}]}]}]
	}`
	_, ok, err := Convert([]byte(rec), "PyPI")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if ok {
		t.Error("a GIT-only entry left nothing to match on; the record must be dropped")
	}
}

func TestConvert_AbsentSeverityStaysAbsent(t *testing.T) {
	// Roughly half of all advisories carry no severity. It must arrive as an
	// empty slice, never as a fabricated default, because slice 4 bands from
	// these vectors and a default would band as a real rating.
	const rec = `{
	  "id": "GHSA-nosev",
	  "affected": [{"package": {"name": "x", "ecosystem": "Go"},
	                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
	}`
	got, ok, err := Convert([]byte(rec), "Go")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Severity) != 0 {
		t.Errorf("Severity = %+v, want empty", got.Severity)
	}
}

func TestConvert_DropsRecordWithNoMatchingAffected(t *testing.T) {
	const rec = `{
	  "id": "GHSA-elsewhere",
	  "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
	                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
	}`
	_, ok, err := Convert([]byte(rec), "Go")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if ok {
		t.Error("record with no Go entries was converted; it must be dropped")
	}
}

func TestConvert_Malformed(t *testing.T) {
	if _, _, err := Convert([]byte("{not json"), "Go"); err == nil {
		t.Error("Convert(malformed) = nil error, want error")
	}
}

// Alpine ships one archive for every release rather than one archive per
// release, so wantEcosystem "Alpine" has to match any "Alpine:vX.Y" entry the
// archive contains (familyMatches), not the exact-but-never-occurring bare
// "Alpine". Narrowing this back to exact equality matches nothing and
// silently ingests zero Alpine records — the failure this test guards.
func TestConvert_AlpineFamilyMatchesAnyRelease(t *testing.T) {
	const rec = `{
	  "id": "CVE-multi-release",
	  "affected": [
	    {"package": {"name": "libssl3", "ecosystem": "Alpine:v3.19"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.4-r0"}]}]},
	    {"package": {"name": "libssl3", "ecosystem": "Alpine:v3.24"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.3.0-r0"}]}]}
	  ]
	}`
	got, ok, err := Convert([]byte(rec), "Alpine")
	if err != nil || !ok {
		t.Fatalf("Convert(_, \"Alpine\"): ok=%v err=%v, want a converted advisory", ok, err)
	}
	// Both releases must survive: the family match decides whether the RECORD
	// is kept, not which of its entries are. Stripping the non-"want" release
	// here would repeat the slice-1 cross-ecosystem bug in a new place.
	if len(got.Affected) != 2 {
		t.Errorf("Affected = %d entries, want both releases kept (v3.19 and v3.24): %+v",
			len(got.Affected), got.Affected)
	}
}

// Widening the family match beyond Alpine would be a silent scope expansion:
// "Go" must never start matching "GoFoo" or any other prefixed ecosystem.
func TestConvert_LanguageEcosystemsStayExactMatch(t *testing.T) {
	const rec = `{
	  "id": "GHSA-gofoo",
	  "affected": [{"package": {"name": "x", "ecosystem": "GoFoo"},
	                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
	}`
	if _, ok, err := Convert([]byte(rec), "Go"); err != nil || ok {
		t.Errorf("Convert(_, \"Go\") on a GoFoo-only record = ok %v err %v, want dropped: "+
			"exact match must not degrade to a prefix match outside Alpine", ok, err)
	}
}

// The authoring database comes from the record's own identifier, resolved
// once at ingest. Every namespace the live database actually contains is
// covered, plus the nesting case that makes prefix-parsing at query time a
// bad idea: ALPINE-CVE-2025-46394 is an ALPINE record, not a CVE one.
func TestDatabaseOf(t *testing.T) {
	for in, want := range map[string]string{
		"GHSA-w24h-v9qh-8gxj":   "GHSA",
		"PYSEC-2022-191":        "PYSEC",
		"GO-2026-4970":          "GO",
		"ALPINE-CVE-2025-46394": "ALPINE",
		"CVE-2021-41092":        "CVE",
		"BIT-golang-2026-39822": "BIT",
		"MAL-2024-1":            "MAL",
	} {
		if got := databaseOf(in); got != want {
			t.Errorf("databaseOf(%q) = %q, want %q", in, got, want)
		}
	}
	// An identifier with no namespace is not silently given one. An empty
	// Database renders as a rating from a source with no name, which is
	// worse than a loud refusal.
	for _, bad := range []string{"", "nodashes", "-leading"} {
		if got := databaseOf(bad); got != "" {
			t.Errorf("databaseOf(%q) = %q, want empty", bad, got)
		}
	}
}

// Every record the provider emits carries a Database. A record without one
// produces a rating attributed to nobody, which is the opposite of what D25
// is for.
func TestConvert_SetsTheDatabase(t *testing.T) {
	for _, tt := range []struct{ id, want string }{
		{"GHSA-w24h-v9qh-8gxj", "GHSA"},
		{"PYSEC-2022-191", "PYSEC"},
		{"ALPINE-CVE-2025-46394", "ALPINE"},
	} {
		// "versions" is the minimum an affected entry needs to survive the
		// pre-existing "nothing left to match on" guard (TestConvert_Drops-
		// GitOnlyAffected exercises the same guard deliberately); this test's
		// subject is Database propagation, not version data.
		rec := `{"id":"` + tt.id + `","affected":[{"package":` +
			`{"ecosystem":"PyPI","name":"django"},"versions":["1"]}]}`
		got, ok, err := Convert([]byte(rec), "PyPI")
		if err != nil || !ok {
			t.Fatalf("Convert(%s) = ok:%v err:%v", tt.id, ok, err)
		}
		if got.Database != tt.want {
			t.Errorf("Convert(%s).Database = %q, want %q", tt.id, got.Database, tt.want)
		}
	}
}

// The schema bump is what stops an older database from serving records with
// no Database at all.
func TestSchemaVersionIs5(t *testing.T) {
	if store.SchemaVersion != 5 {
		t.Errorf("SchemaVersion = %d, want 5 — D25 adds a field, and a database "+
			"built without it must refuse rather than report unattributed ratings",
			store.SchemaVersion)
	}
}
