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

// Schema 9 exists for the composite-key advisory index (D67) — the
// "advisories" bucket's key became "<eco>\x00<name>\x00<advisoryID>", so a
// database built before this must refuse rather than have Lookup silently
// find nothing against its old JSON-array shape. Pinned to the current value
// rather than a relation (e.g. ">= 5") so this fails loudly the moment a
// later bump is not reflected here, instead of silently agreeing with
// whatever the constant happens to be.
//
// Duplicated deliberately, alongside store.TestSchemaVersionIs9: that copy
// pins the value from the package that owns SchemaVersion and enforces
// ErrSchemaMismatch; this one pins it from the provider package whose
// on-disk assumptions (Convert always setting Database, tested above) depend
// on the schema being at least what D25 required. Someone working only in
// this package, and never running internal/store's suite, still gets a
// visible failure the moment the two disagree.
func TestSchemaVersionIs9(t *testing.T) {
	if store.SchemaVersion != 9 {
		t.Errorf("SchemaVersion = %d, want 9 — schema 9 replaces the advisory "+
			"index's JSON-array value with composite keys, and a database built "+
			"before that must refuse rather than silently return no advisories "+
			"for every package", store.SchemaVersion)
	}
}

// D35: the repair has to be wired into ingestion, not merely to exist. Every
// apk `fixed` bound in the v7 database that will not parse is this shape — 11
// occurrences across irssi and mariadb — and repairBound passing its own unit
// test proves nothing about whether Convert calls it.
func TestConvert_RepairsAlpineRevisionTypo(t *testing.T) {
	const rec = `{
	  "id": "ALPINE-CVE-2017-9468",
	  "affected": [{
	    "package": {"ecosystem": "Alpine:v3.5", "name": "irssi"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [
	      {"introduced": "0"},
	      {"fixed": "0.8.21.r2"}
	    ]}]
	  }]
	}`
	got, ok, err := Convert([]byte(rec), "Alpine")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if !ok {
		t.Fatal("Convert returned ok=false")
	}
	ev := got.Affected[0].Ranges[0].Events
	if len(ev) != 2 {
		t.Fatalf("events = %d, want 2", len(ev))
	}
	if ev[1].Fixed != "0.8.21-r2" {
		t.Errorf("fixed = %q, want %q — the repair is not reaching ingestion",
			ev[1].Fixed, "0.8.21-r2")
	}
	// The sentinel is not a version and must survive untouched; a repair that
	// reached it would be rewriting the one bound the range layer resolves
	// specially.
	if ev[0].Introduced != "0" {
		t.Errorf("introduced = %q, want the sentinel %q", ev[0].Introduced, "0")
	}
}

// ...and it must not reach a bound that already parses, in any ecosystem. A
// repair that fired on good data would be undetectable downstream: the database
// would simply hold a version nobody published.
func TestConvert_LeavesGoodBoundsAlone(t *testing.T) {
	const rec = `{
	  "id": "ALPINE-CVE-2022-0778",
	  "affected": [{
	    "package": {"ecosystem": "Alpine:v3.14", "name": "libretls"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [
	      {"introduced": "0"},
	      {"fixed": "3.3.3p1-r3"}
	    ]}]
	  }]
	}`
	got, _, err := Convert([]byte(rec), "Alpine")
	if err != nil {
		t.Fatal(err)
	}
	if fixed := got.Affected[0].Ranges[0].Events[1].Fixed; fixed != "3.3.3p1-r3" {
		t.Errorf("fixed = %q, want it stored exactly as published", fixed)
	}
}

// familyMatches was written with "Alpine" hardcoded, and Debian arriving turned
// that into an archive of 62,318 records yielding zero. The fetch guard caught
// it; this pins the rule so it cannot regress to a name list.
func TestFamilyMatches_IsGeneralNotAName(t *testing.T) {
	for _, tc := range []struct {
		ecosystem, want string
		match           bool
	}{
		{"Alpine:v3.19", "Alpine", true},
		{"Alpine", "Alpine", true},
		{"Debian:12", "Debian", true},
		{"Debian", "Debian", true},
		{"Ubuntu:24.04:LTS", "Ubuntu", true},   // whenever Ubuntu arrives, this already holds
		{"Rocky Linux:9", "Rocky Linux", true}, // and again for Rocky Linux (D71)
		{"AlmaLinux:9", "AlmaLinux", true},     // and again for AlmaLinux (D72)
		{"Go", "Go", true},
		// D88: fetching "Chainguard" also covers a "Wolfi" entry in the SAME
		// record (one feed, two keys) -- but the reverse never happens,
		// because nothing in this codebase ever fetches under "Wolfi".
		{"Wolfi", "Chainguard", true},
		{"Chainguard", "Wolfi", false},
		{"Chainguard", "Chainguard", true},
		{"Wolfi", "Wolfi", true},
		// D95 (QA round 5): fetching "Alpaquita" also covers a BellSoft
		// Hardened Containers entry in the same record, in BOTH the bare and
		// the release-qualified spellings. The bare form is unreachable in
		// today's archive (0 occurrences measured) but is a live branch, and
		// dropping its disjunct stayed green until this row.
		{"BellSoft Hardened Containers", "Alpaquita", true},
		{"BellSoft Hardened Containers:25", "Alpaquita", true},
		{"Alpaquita", "Alpaquita", true},
		// A family must not swallow a differently named one that starts the
		// same way. Without the colon in the prefix test, "Debian" would match
		// a hypothetical "DebianExtra".
		{"DebianExtra", "Debian", false},
		{"AlpineLinux:v3.19", "Alpine", false},
		{"Debian:12", "Alpine", false},
		{"npm", "Go", false},
	} {
		if got := familyMatches(tc.ecosystem, tc.want); got != tc.match {
			t.Errorf("familyMatches(%q, %q) = %v, want %v", tc.ecosystem, tc.want, got, tc.match)
		}
	}
}

// TestConvert_DropsBugfixAndEnhancementErrata pins ALBA and ALEA directly at
// Convert, alongside TestConvert_DropsWithdrawn and TestConvert_DropsMalicious
// above (same file, same pattern) -- TestFetch_AlmaLinuxDropsBugfixAndEnhance-
// mentErrata in fetch_test.go already drove this through the caller (Fetch)
// first; this is the narrower unit coverage for the two branches that test
// cannot reach on its own (a mix that also names ALSA, so a single dropped
// record cannot make the archive-level zero-records guard fire instead of
// exercising the drop).
func TestConvert_DropsBugfixAndEnhancementErrata(t *testing.T) {
	for _, id := range []string{"ALBA-2026-0001", "ALEA-2026-0002"} {
		rec := `{"id":"` + id + `","related":["CVE-2026-1"],` +
			`"affected":[{"package":{"name":"bash","ecosystem":"AlmaLinux:9"},` +
			`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`
		_, ok, err := Convert([]byte(rec), "AlmaLinux")
		if err != nil {
			t.Fatalf("Convert(%s): %v", id, err)
		}
		if ok {
			t.Errorf("%s was converted; ALBA and ALEA name no vulnerability and must be dropped (D72)", id)
		}
	}
	// An ALSA record must NOT be caught by the same guard -- distinguishing
	// "starts with ALSA" from "starts with AL" is the point.
	const alsa = `{"id":"ALSA-2026-0003","related":["CVE-2026-1"],
	  "affected":[{"package":{"name":"bash","ecosystem":"AlmaLinux:9"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`
	if _, ok, err := Convert([]byte(alsa), "AlmaLinux"); err != nil || !ok {
		t.Errorf("ALSA record: ok=%v err=%v, want it kept -- only ALBA and ALEA are dropped", ok, err)
	}
}

// TestConvert_RelatedIsScopedToDistroAuthoredRecords is D71 decision 1's own
// hazard, pinned directly: a GHSA record's `related` names genuinely
// different, merely similar advisories, and reading it as an alias would
// fabricate a join between two distinct vulnerabilities. Without the scope, a
// mutation that widened Related population to every record would pass every
// other test in this package (nothing else asserts GHSA's Related is empty)
// while silently starting to misjoin language-ecosystem records.
func TestConvert_RelatedIsScopedToDistroAuthoredRecords(t *testing.T) {
	const ghsa = `{"id":"GHSA-aaaa-bbbb-cccc","related":["GHSA-similar-but-different"],
	  "affected":[{"package":{"name":"x","ecosystem":"Go"},
	    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
	got, ok, err := Convert([]byte(ghsa), "Go")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Related) != 0 {
		t.Errorf("Related = %v, want empty -- GHSA's `related` names a DIFFERENT "+
			"advisory, not an alias for this one", got.Related)
	}

	const alsa = `{"id":"ALSA-2026-0004","related":["CVE-2026-40004"],
	  "affected":[{"package":{"name":"bash","ecosystem":"AlmaLinux:9"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`
	got, ok, err = Convert([]byte(alsa), "AlmaLinux")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Related) != 1 || got.Related[0] != "CVE-2026-40004" {
		t.Errorf("Related = %v, want [CVE-2026-40004] -- ALSA IS distro-authored, "+
			"and this is the only field carrying its CVE", got.Related)
	}

	// D88: CGA (Chainguard's own namespace) joins the same scope. `related`
	// carries both the CVE and a GHSA sibling id in real records (measured
	// shape) -- both must survive, since lookupIDs treats a shared identifier
	// as the SAME advisory here, unlike GHSA's own `related` above.
	const cga = `{"id":"CGA-224q-ccj5-2p53","related":["CVE-2025-32464","GHSA-frg5-h47x-75j9"],
	  "affected":[{"package":{"name":"haproxy-3.0","ecosystem":"Chainguard"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.10-r0"}]}]}]}`
	got, ok, err = Convert([]byte(cga), "Chainguard")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Related) != 2 || got.Related[0] != "CVE-2025-32464" || got.Related[1] != "GHSA-frg5-h47x-75j9" {
		t.Errorf("Related = %v, want [CVE-2025-32464 GHSA-frg5-h47x-75j9] -- CGA IS "+
			"distro-authored, and `related` is the only field carrying its CVE "+
			"(measured 2026-08-22: aliases 0.2%%, upstream 0%%)", got.Related)
	}
}

// TestConvert_VendorSeverityWordOnlyWhenDistroAuthoredAndNoCVSS pins the two
// guards on the VENDOR_WORD entry itself: it must not fire outside a
// distro-authored record (a language-ecosystem summary starting with one of
// the four words by coincidence must not be mistaken for a vendor rating),
// and it must not fire when the record already carries a real CVSS vector
// (D13: store what was published, and a record with a vector published one).
func TestConvert_VendorSeverityWordOnlyWhenDistroAuthoredAndNoCVSS(t *testing.T) {
	// A GHSA summary that happens to start with "Word:" -- the exact shape
	// vendorSeverityWord's regex looks for -- must not gain a fabricated
	// VENDOR_WORD rating just because the text matches. Without the colon
	// after "Critical" this fixture would be rejected by the regex alone,
	// regardless of whether the distroAuthored gate ran at all -- proven by
	// mutation: replacing "distroAuthored(db)" with "true" left this test
	// green when the summary read "Critical bug in a parser" (no colon).
	const ghsa = `{"id":"GHSA-wordy","summary":"Critical: bug in a parser",
	  "affected":[{"package":{"name":"x","ecosystem":"Go"},
	    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
	got, ok, err := Convert([]byte(ghsa), "Go")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Severity) != 0 {
		t.Errorf("Severity = %+v, want empty -- GHSA is not distro-authored, so its "+
			"summary's leading word must not become a rating", got.Severity)
	}

	// An ALSA record that already carries a real CVSS vector must not also
	// gain a VENDOR_WORD entry alongside it.
	const alsaWithCVSS = `{"id":"ALSA-2026-0005","summary":"Important: has a real vector too",
	  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	  "affected":[{"package":{"name":"bash","ecosystem":"AlmaLinux:9"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`
	got, ok, err = Convert([]byte(alsaWithCVSS), "AlmaLinux")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Severity) != 1 || got.Severity[0].Type != "CVSS_V3" {
		t.Errorf("Severity = %+v, want only the CVSS_V3 entry -- a record that HAS a "+
			"vector must not also get a fabricated VENDOR_WORD one", got.Severity)
	}

	// An ALSA record with no severity and an unrecognized leading word gets
	// no VENDOR_WORD entry either -- an unrecognized word is not guessed at.
	const alsaUnrecognized = `{"id":"ALSA-2026-0006","summary":"Sev4: openssh update",
	  "affected":[{"package":{"name":"bash","ecosystem":"AlmaLinux:9"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`
	got, ok, err = Convert([]byte(alsaUnrecognized), "AlmaLinux")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Severity) != 0 {
		t.Errorf("Severity = %+v, want empty -- \"Sev4\" is not one of the four "+
			"recognized words", got.Severity)
	}

	// The ordinary case: an ALSA record with no CVSS and a recognized word
	// gets exactly one VENDOR_WORD entry carrying it.
	const alsaWordOnly = `{"id":"ALSA-2026-0007","summary":"Moderate: openssh update",
	  "affected":[{"package":{"name":"bash","ecosystem":"AlmaLinux:9"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`
	got, ok, err = Convert([]byte(alsaWordOnly), "AlmaLinux")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Severity) != 1 || got.Severity[0].Type != "VENDOR_WORD" || got.Severity[0].Score != "Moderate" {
		t.Errorf("Severity = %+v, want one VENDOR_WORD entry scored \"Moderate\"", got.Severity)
	}
}

// TestDistroAuthored is the classifier's own table -- adversarial on both
// sides, since the scope guard above only exercises one row of each.
func TestDistroAuthored(t *testing.T) {
	for db, want := range map[string]bool{
		"ALPINE": true, "DEBIAN": true, "UBUNTU": true, "RLSA": true,
		"ALSA": true, "ALBA": true, "ALEA": true,
		// D88: Chainguard's own advisory namespace joins the same scope --
		// its records carry the CVE nowhere else at all (measured 2026-08-22:
		// aliases 0.2%, upstream 0%, related 99.7% with a CVE on 95.9%).
		"CGA":  true,
		"GHSA": false, "PYSEC": false, "GO": false, "RUSTSEC": false,
		"CVE": false, "BIT": false, "MAL": false, "": false,
		// Adversarial: a namespace that merely starts with a distro one's
		// letters must not match by accident (distroAuthored is a switch on
		// the whole string, not a prefix test, but a mutation that changed
		// it to strings.HasPrefix would pass every row above and only this
		// one would catch it).
		"ALSAX": false, "AL": false, "CGAX": false, "CG": false,
		// D92: MinimOS and Echo deliberately did NOT join this scope -- both
		// carry their CVE in `upstream` (measured 2026-08-26: 94.9% and 98.9%
		// respectively), which D3's existing read already covers, so neither
		// needed the `related` join Chainguard/AlmaLinux needed. Asserted here
		// so a future change cannot add either without it being a deliberate,
		// reviewed edit to this table.
		"MINI": false, "ECHO": false,
	} {
		if got := distroAuthored(db); got != want {
			t.Errorf("distroAuthored(%q) = %v, want %v", db, got, want)
		}
	}
}

// TestConvert_MinimOSAndEchoUpstreamCVEReachesStoredAdvisory is D92's
// caller-first test for both new distros: unlike Chainguard/AlmaLinux
// (TestConvert_RelatedIsScopedToDistroAuthoredRecords above), neither needed
// a distroAuthored scope change -- the CVE lives in `upstream` on 94.9% of
// MinimOS's MINI-* records and 98.9% of Echo's ECHO-* records (measured
// 2026-08-26), and D3 already reads that field for every record regardless
// of database. This proves the field actually survives Convert for both new
// ecosystems rather than merely for the ones distroAuthored already covered
// -- deleting either family's Ecosystems entry (fetch.go) does not touch
// this test at all, since Convert takes no ecosystems list; that half is
// covered separately by the zero-record guard test in fetch_test.go.
//
// Fixtures are real, trimmed records: MINI-2222-4958-pc3h and
// ECHO-0066-dd81-6847 (measured 2026-08-26 against the live archives).
func TestConvert_MinimOSAndEchoUpstreamCVEReachesStoredAdvisory(t *testing.T) {
	const mini = `{"id":"MINI-2222-4958-pc3h","upstream":["CVE-2026-56865"],
	  "affected":[{"package":{"name":"buildpacks-lifecycle-0.21","ecosystem":"MinimOS"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0.21.6-r1"}]}]}]}`
	got, ok, err := Convert([]byte(mini), "MinimOS")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Upstream) != 1 || got.Upstream[0] != "CVE-2026-56865" {
		t.Errorf("Upstream = %v, want [CVE-2026-56865]", got.Upstream)
	}

	const echo = `{"id":"ECHO-0051-e755-e08e","upstream":["CVE-2026-4424"],
	  "affected":[{"package":{"name":"libarchive","ecosystem":"Echo","purl":"pkg:deb/echo/libarchive"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.7.4-4+e5"}]}]}]}`
	got, ok, err = Convert([]byte(echo), "Echo")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Upstream) != 1 || got.Upstream[0] != "CVE-2026-4424" {
		t.Errorf("Upstream = %v, want [CVE-2026-4424]", got.Upstream)
	}
}

// TestConvert_EchoNotAffectedSentinel drives convert directly (unexported,
// same package) so the D92 stats counter can be asserted -- Convert itself
// (the public, stats-less wrapper) cannot show it, the same reason
// TestConvert_ModuleStream_ZeroTokensStaysStreamless (modulestream_test.go)
// does the same for D82's counters.
//
// The first half is the real record ECHO-0066-dd81-6847 (measured
// 2026-08-26): its only affected entry is package `linux` with a range
// whose sole Fixed event is the bare sentinel "1". Dropping that range
// leaves the entry with no ranges and no enumerated versions, which the
// existing "nothing left to match on" guard (record.go) then drops too --
// so the whole record must convert with ok=false, not merely a
// shorter-than-expected Affected list. Deleting the sentinel drop in
// convert() turns this red on both ok and the counter, while
// TestConvert_MinimOSAndEchoUpstreamCVEReachesStoredAdvisory above (which
// never builds a fixed:"1" fixture) stays green.
//
// The second half is the negative row D92 explicitly asked for: a GENUINE
// Echo fix at epoch 1 ("1:1.0-1") is a different string entirely and must
// survive untouched, proving the guard matches the exact sentinel string
// rather than "any fixed version starting with 1" -- a version-agnostic
// drop would wrongly discard every real epoch-1 fix Echo ever publishes.
func TestConvert_EchoNotAffectedSentinel(t *testing.T) {
	const linuxSentinel = `{"id":"ECHO-0066-dd81-6847","upstream":["CVE-2025-38090"],
	  "affected":[{"package":{"name":"linux","ecosystem":"Echo","purl":"pkg:deb/echo/linux"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`
	var st stats
	got, ok, err := convert([]byte(linuxSentinel), "Echo", &st, nil)
	if err != nil {
		t.Fatalf("convert: err=%v", err)
	}
	if ok {
		t.Fatalf("convert: ok=true, want false -- the record's only affected "+
			"entry is a not-affected sentinel with nothing left to match on, got %+v", got)
	}
	if st.EchoNotAffectedSentinel != 1 {
		t.Errorf("EchoNotAffectedSentinel = %d, want 1", st.EchoNotAffectedSentinel)
	}

	const epochOneFix = `{"id":"ECHO-003f-2632-599c","upstream":["CVE-2026-99999"],
	  "affected":[{"package":{"name":"openssh","ecosystem":"Echo","purl":"pkg:deb/echo/openssh"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:1.0-1"}]}]}]}`
	st = stats{}
	got, ok, err = convert([]byte(epochOneFix), "Echo", &st, nil)
	if err != nil || !ok {
		t.Fatalf("convert: ok=%v err=%v, want the genuine epoch-1 fix kept", ok, err)
	}
	if len(got.Affected) != 1 || len(got.Affected[0].Ranges) != 1 {
		t.Fatalf("Affected = %+v, want one entry with its range intact", got.Affected)
	}
	events := got.Affected[0].Ranges[0].Events
	if fixed := events[len(events)-1].Fixed; fixed != "1:1.0-1" {
		t.Errorf("Fixed = %q, want %q -- the sentinel guard must not touch a genuine epoch fix", fixed, "1:1.0-1")
	}
	if st.EchoNotAffectedSentinel != 0 {
		t.Errorf("EchoNotAffectedSentinel = %d, want 0 -- a real fix must never increment the sentinel counter", st.EchoNotAffectedSentinel)
	}
}
