package scancmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// D113's caller tests. Every one drives Run end to end against a real bolt
// database and a real docker-archive image, because each rule D113 changes is
// decided by what the INVENTORY holds — a checkDBAge test handed a key list by
// hand would pass while Run computed the wrong one, or none.
//
// Dates are relative to the wall clock because Run reads time.Now() itself;
// the ages are whole days apart from every threshold, so a slow machine cannot
// move a row across one.

const amazonProvider = "Amazon Linux ALAS"

// osReleaseAL2 is a real amazonlinux:2 /etc/os-release, trimmed. ID amzn and
// VERSION_ID 2 key the inventory on "Amazon Linux:2" (D73).
const osReleaseAL2 = `NAME="Amazon Linux"
VERSION="2"
ID="amzn"
ID_LIKE="centos rhel fedora"
VERSION_ID="2"
PRETTY_NAME="Amazon Linux 2"
`

// al2Files is an Amazon Linux 2 image: the shared sqlite rpmdb fixture behind
// an AL2 os-release, so every package is keyed "Amazon Linux:2".
func al2Files(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		osReleasePath:              osReleaseAL2,
		"var/lib/rpm/rpmdb.sqlite": fixtureBytes(t, rpmFixture),
	}
}

// d113DB writes a database holding m as its metadata and the one clean Alpine
// 3.19 advisory d111DB uses, so an Alpine scan that gets past the age checks
// is evaluated, clean, and exits 0.
func d113DB(t *testing.T, m store.Meta) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "ALPINE-2024-0001", Kind: advisory.KindVulnerability, Database: "ALPINE",
		Upstream: []string{"CVE-2024-99001"},
		Severity: []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}},
		Affected: []advisory.Affected{{
			Ecosystem: "Alpine:v3.19", Name: "busybox",
			Ranges: []advisory.Range{{Type: advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.36.1-r10"}}}},
		}},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := w.SetMeta(m); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func daysAgo(n int) time.Time { return time.Now().AddDate(0, 0, -n) }

func ymd(t time.Time) string { return t.UTC().Format("2006-01-02") }

// (1) Scope. The 2026-09-30 review's reproduction: the published artifact's
// floor was one finished Amazon extras topic, so an Alpine scan under
// --db-max-age 24h exited 2 over a feed it never consulted. The same database
// still refuses a scan that DOES use the stale provider — the half that proves
// the scope narrowed the check rather than dropping it.
func TestRun_D113_AgeIsJudgedForTheKeysTheScanUses(t *testing.T) {
	stale := daysAgo(90)
	db := d113DB(t, store.Meta{Providers: map[string]store.Provenance{
		"osv":          {Ecosystems: []string{"Alpine:v3.19"}, DataAsOf: time.Now()},
		amazonProvider: {Ecosystems: []string{"Amazon Linux:2"}, DataAsOf: stale},
	}})
	opts := Options{DBMaxAge: 24 * time.Hour}

	out, errOut, code := scanImage(t, db, alpine319Files(), opts)
	if code != 0 {
		t.Fatalf("Alpine scan = %d, want 0 — the only stale provider declares no key this "+
			"inventory holds\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if strings.Contains(errOut, "db-max-age") {
		t.Errorf("a passing scan still mentions the age gate:\n%s", errOut)
	}

	out, errOut, code = scanImage(t, db, al2Files(t), opts)
	if code != 2 {
		t.Fatalf("AL2 scan = %d, want 2 — %s declares Amazon Linux:2 and is 90 days old\n"+
			"stdout: %s\nstderr: %s", code, amazonProvider, out, errOut)
	}
	want := "error: vulnerability data is 90 days old (" + amazonProvider + ", as of " + ymd(stale) +
		"), past the 24h0m0s allowed by --db-max-age"
	if !strings.Contains(errOut, want) {
		t.Errorf("stderr does not carry the D59 refusal for the in-scope provider\nwant: %s\ngot:\n%s", want, errOut)
	}
	if out != "" {
		t.Errorf("a refused scan wrote a report to stdout:\n%s", out)
	}
}

// (2) Frozen. A key frozen a hundred days passed a 24-hour gate because the
// provider's own DataAsOf was that morning's — the store's invariant ("a
// frozen key must not read as fresher than its data", D110) contradicted by
// the one check that exists to act on freshness. The refusal names the key and
// the freeze, which D111's coverage[] also prints.
func TestRun_D113_AFrozenKeyIsAsOldAsItsFreeze(t *testing.T) {
	since := daysAgo(100)
	frozen := d113DB(t, store.Meta{Providers: map[string]store.Provenance{
		"osv": {
			Ecosystems: []string{"Alpine:v3.19"},
			DataAsOf:   time.Now(),
			Frozen:     map[string]time.Time{"Alpine:v3.19": since},
		},
	}})
	opts := Options{DBMaxAge: 24 * time.Hour}

	out, errOut, code := scanImage(t, frozen, alpine319Files(), opts)
	if code != 2 {
		t.Fatalf("Run = %d, want 2 — Alpine:v3.19 has been frozen 100 days\nstdout: %s\nstderr: %s",
			code, out, errOut)
	}
	want := "error: vulnerability data for Alpine:v3.19 is 100 days old (osv, frozen since " +
		ymd(since) + "), past the 24h0m0s allowed by --db-max-age"
	if !strings.Contains(errOut, want) {
		t.Errorf("stderr does not name the frozen key and its date\nwant: %s\ngot:\n%s", want, errOut)
	}
	if out != "" {
		t.Errorf("a refused scan wrote a report to stdout:\n%s", out)
	}

	// The same key live, the same provider date: passes. Without this half a
	// check that refused every frozen-looking fixture for some other reason
	// would satisfy the assertion above.
	live := d113DB(t, store.Meta{Providers: map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Alpine:v3.19"}, DataAsOf: time.Now()},
	}})
	if out, errOut, code := scanImage(t, live, alpine319Files(), opts); code != 0 {
		t.Errorf("live key Run = %d, want 0\nstdout: %s\nstderr: %s", code, out, errOut)
	}
}

// (3) An unknown age is refused only where it matters. D59's rule — a provider
// that recorded no date has not said it is fresh — still holds inside the set;
// a provider the scan does not use and that recorded no date is no more this
// scan's concern than its age would be.
func TestRun_D113_UnknownAgeIsRefusedOnlyInsideTheSet(t *testing.T) {
	db := d113DB(t, store.Meta{Providers: map[string]store.Provenance{
		"osv":          {Ecosystems: []string{"Alpine:v3.19"}, DataAsOf: time.Now()},
		amazonProvider: {Ecosystems: []string{"Amazon Linux:2"}}, // no DataAsOf
	}})
	opts := Options{DBMaxAge: 24 * time.Hour}

	out, errOut, code := scanImage(t, db, alpine319Files(), opts)
	if code != 0 {
		t.Fatalf("Alpine scan = %d, want 0 — the undated provider is outside the set\n"+
			"stdout: %s\nstderr: %s", code, out, errOut)
	}

	out, errOut, code = scanImage(t, db, al2Files(t), opts)
	if code != 2 {
		t.Fatalf("AL2 scan = %d, want 2 — the undated provider declares Amazon Linux:2\n"+
			"stdout: %s\nstderr: %s", code, out, errOut)
	}
	want := "error: --db-max-age given, but " + amazonProvider + " did not record when its " +
		"data was current, so this database's age cannot be established"
	if !strings.Contains(errOut, want) {
		t.Errorf("stderr does not carry D59's unknown-age refusal\nwant: %s\ngot:\n%s", want, errOut)
	}
	// Only the in-scope provider is named: osv recorded a date.
	if strings.Contains(errOut, "osv did not record") || strings.Contains(errOut, "osv and") {
		t.Errorf("the refusal names a provider that recorded a date:\n%s", errOut)
	}
}

// (4) Ratings get their own gate. --db-max-rating-age refuses stale NVD data;
// without it the same database scans; and --db-max-age alone still ignores
// ratings (D59's reason stands: stale prose must not fail a build), which is
// why the answer is a second flag rather than a wider first one.
func TestRun_D113_RatingsHaveTheirOwnGate(t *testing.T) {
	stale := daysAgo(90)
	db := d113DB(t, store.Meta{
		Providers: map[string]store.Provenance{
			"osv": {Ecosystems: []string{"Alpine:v3.19"}, DataAsOf: time.Now()},
		},
		Ratings: map[string]store.Provenance{
			"EPSS": {DataAsOf: time.Now()},
			"NVD":  {DataAsOf: stale},
		},
	})

	out, errOut, code := scanImage(t, db, alpine319Files(), Options{DBMaxRatingAge: 24 * time.Hour})
	if code != 2 {
		t.Fatalf("Run(--db-max-rating-age 24h) = %d, want 2 — NVD is 90 days old\n"+
			"stdout: %s\nstderr: %s", code, out, errOut)
	}
	want := "error: rating data is 90 days old (NVD, as of " + ymd(stale) +
		"), past the 24h0m0s allowed by --db-max-rating-age"
	if !strings.Contains(errOut, want) {
		t.Errorf("stderr does not carry the rating refusal\nwant: %s\ngot:\n%s", want, errOut)
	}
	if out != "" {
		t.Errorf("a refused scan wrote a report to stdout:\n%s", out)
	}

	if out, errOut, code := scanImage(t, db, alpine319Files(), Options{}); code != 0 {
		t.Errorf("Run without the flag = %d, want 0\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	// D59 unchanged: the advisory gate does not read ratings.
	if out, errOut, code := scanImage(t, db, alpine319Files(), Options{DBMaxAge: 24 * time.Hour}); code != 0 {
		t.Errorf("Run(--db-max-age 24h) with fresh advisories and stale ratings = %d, want 0\n"+
			"stdout: %s\nstderr: %s", code, out, errOut)
	}
}

// (4b) A rating source that recorded no date is refused under the rating
// gate, the same D17 discipline D59 applies to advisory providers.
func TestRun_D113_UndatedRatingSourceIsRefused(t *testing.T) {
	db := d113DB(t, store.Meta{
		Providers: map[string]store.Provenance{
			"osv": {Ecosystems: []string{"Alpine:v3.19"}, DataAsOf: time.Now()},
		},
		Ratings: map[string]store.Provenance{
			"NVD": {DataAsOf: time.Now()},
			"KEV": {}, // no DataAsOf
		},
	})
	var out, errOut bytes.Buffer
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, alpine319Files())
	code := Run(context.Background(), db, "docker-archive:"+tarPath,
		Options{DBMaxRatingAge: 24 * time.Hour}, &out, &errOut)
	if code != 2 {
		t.Fatalf("Run = %d, want 2 — KEV recorded no date\nstderr: %s", code, errOut.String())
	}
	want := "error: --db-max-rating-age given, but KEV did not record when its data was current"
	if !strings.Contains(errOut.String(), want) {
		t.Errorf("stderr does not carry the unknown-age refusal\nwant: %s\ngot:\n%s", want, errOut.String())
	}
}
