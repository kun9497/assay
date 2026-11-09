package scancmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// D113 revised (2026-11-09): a key the provider dated on its own
// (Provenance.KeyAsOf) is judged by that date, not by the provider's. The
// case that forced it is the published artifact's own: the amazon provider
// declares Amazon Linux:2 and Amazon Linux:2023 with one DataAsOf, and that
// date is set by one quiet AL2 extras topic (ansible2, 2025-03-06 on
// sha256:ddd969bc, twenty months silent and under the two-year closure), so
// every AL2023 image scan under --db-max-age=168h was refused for a date that
// was not its data's -- with the remedy "run `assay db update`", which could
// not help. Caller first (CLAUDE.md): Run, through the real image path.

// osReleaseAL2023 keys the inventory on "Amazon Linux:2023" (D73).
const osReleaseAL2023 = `NAME="Amazon Linux"
VERSION="2023"
ID="amzn"
ID_LIKE="fedora"
VERSION_ID="2023"
PRETTY_NAME="Amazon Linux 2023"
`

func al2023Files(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		osReleasePath:              osReleaseAL2023,
		"var/lib/rpm/rpmdb.sqlite": fixtureBytes(t, rpmFixture),
	}
}

func TestRun_D113Revised_AKeyIsJudgedByItsOwnDate(t *testing.T) {
	stale, fresh := daysAgo(90), time.Now()
	db := d113DB(t, store.Meta{Providers: map[string]store.Provenance{
		amazonProvider: {
			Ecosystems: []string{"Amazon Linux:2", "Amazon Linux:2023"},
			DataAsOf:   stale, // the provider-wide minimum: AL2's
			KeyAsOf:    map[string]time.Time{"Amazon Linux:2": stale, "Amazon Linux:2023": fresh},
		},
	}})
	opts := Options{DBMaxAge: 24 * time.Hour, Output: "json"}

	// AL2023 is dated by its own repositories and passes the gate...
	out, errOut, code := scanImage(t, db, al2023Files(t), opts)
	if code == 2 {
		t.Fatalf("AL2023 scan = 2, want it past the age gate: its own data is current\nstderr: %s", errOut)
	}
	if strings.Contains(errOut, "--db-max-age") {
		t.Errorf("a passing AL2023 scan still mentions the age gate:\n%s", errOut)
	}
	// ...and the report's coverage[] carries the key's own date, not the
	// provider's (D111 reads the same per-key date).
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
	}
	var recs []d111Coverage
	if err := json.Unmarshal(raw["coverage"], &recs); err != nil || len(recs) != 1 {
		t.Fatalf("coverage = %s (%v), want one Amazon Linux:2023 record", raw["coverage"], err)
	}
	if recs[0].Ecosystem != "Amazon Linux:2023" || recs[0].DataAsOf != ymd(fresh) {
		t.Errorf("coverage[0] = %+v, want Amazon Linux:2023 dataAsOf %s (the key's own date, not the provider's %s)",
			recs[0], ymd(fresh), ymd(stale))
	}

	// AL2 is still refused, by its own date, with the live-key remedy.
	out, errOut, code = scanImage(t, db, al2Files(t), opts)
	if code != 2 {
		t.Fatalf("AL2 scan = %d, want 2 -- Amazon Linux:2's own data is 90 days old\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	want := "error: vulnerability data is 90 days old (" + amazonProvider + ", as of " + ymd(stale) +
		"), past the 24h0m0s allowed by --db-max-age"
	if !strings.Contains(errOut, want) {
		t.Errorf("stderr does not carry the refusal for AL2's own date\nwant: %s\ngot:\n%s", want, errOut)
	}
	if out != "" {
		t.Errorf("a refused scan wrote a report to stdout:\n%s", out)
	}

	// The contrast that makes the first half fail if KeyAsOf is ignored: the
	// same provider with no per-key dates refuses AL2023 by AL2's date, which
	// is exactly the 2026-11-09 artifact's behaviour.
	undifferentiated := d113DB(t, store.Meta{Providers: map[string]store.Provenance{
		amazonProvider: {Ecosystems: []string{"Amazon Linux:2", "Amazon Linux:2023"}, DataAsOf: stale},
	}})
	if _, errOut, code := scanImage(t, undifferentiated, al2023Files(t), opts); code != 2 {
		t.Errorf("AL2023 scan on a provider with no per-key date = %d, want 2 by the provider's date\nstderr: %s", code, errOut)
	}
}

// A freeze still wins over the key's own date (D110's invariant: a frozen key
// must not read as fresher than its data): KeyAsOf is when the archive was
// current, the freeze is when the data stopped, and the earlier of the two is
// the age of what the scan reads.
func TestRun_D113Revised_AFreezeStillOutranksTheKeysOwnDate(t *testing.T) {
	since := daysAgo(100)
	db := d113DB(t, store.Meta{Providers: map[string]store.Provenance{
		"osv": {
			Ecosystems: []string{"Alpine:v3.19"},
			DataAsOf:   time.Now(),
			KeyAsOf:    map[string]time.Time{"Alpine:v3.19": time.Now()},
			Frozen:     map[string]time.Time{"Alpine:v3.19": since},
		},
	}})
	out, errOut, code := scanImage(t, db, alpine319Files(), Options{DBMaxAge: 24 * time.Hour})
	if code != 2 {
		t.Fatalf("Run = %d, want 2 -- Alpine:v3.19 has been frozen 100 days whatever its archive date says\nstdout: %s\nstderr: %s",
			code, out, errOut)
	}
	if want := "frozen since " + ymd(since); !strings.Contains(errOut, want) {
		t.Errorf("stderr does not name the freeze\nwant: %s\ngot:\n%s", want, errOut)
	}
}

// A provider whose DataAsOf is unknown (one archive undated) still dates the
// keys it could date: the undated archive's keys are refused as unknown, the
// dated ones are judged on their own date. Before the revision the whole
// provider was unknown and every key under it was refused.
func TestRun_D113Revised_UnknownIsPerKey(t *testing.T) {
	db := d113DB(t, store.Meta{Providers: map[string]store.Provenance{
		amazonProvider: {
			Ecosystems: []string{"Amazon Linux:2", "Amazon Linux:2023"},
			// no DataAsOf: AL2's repositories carried no date
			KeyAsOf: map[string]time.Time{"Amazon Linux:2023": time.Now()},
		},
	}})
	opts := Options{DBMaxAge: 24 * time.Hour}
	if _, errOut, code := scanImage(t, db, al2023Files(t), opts); code == 2 {
		t.Errorf("AL2023 scan = 2, want it past the gate on its own date\nstderr: %s", errOut)
	}
	_, errOut, code := scanImage(t, db, al2Files(t), opts)
	if code != 2 {
		t.Fatalf("AL2 scan = %d, want 2: its date was not recorded", code)
	}
	if want := "error: --db-max-age given, but " + amazonProvider + " did not record when its data was current"; !strings.Contains(errOut, want) {
		t.Errorf("stderr does not carry the unknown-age refusal\nwant: %s\ngot:\n%s", want, errOut)
	}
}

// A whole-key frozen key as carry-forward now stores it: Frozen[key] and
// KeyAsOf[key] both hold the freeze, while the provider's DataAsOf is older
// still (its stalest LIVE archive, the CleanStart shape). The gate must judge
// the key by its freeze and name it -- before KeyAsOf, the provider's older
// date won the min and the refusal was the live-key one with the live-key
// remedy, for a key `db update` cannot refresh.
func TestRun_D113Revised_ACarriedKeyIsJudgedByItsFreezeNotTheProvidersStalestArchive(t *testing.T) {
	since := daysAgo(100)
	db := d113DB(t, store.Meta{Providers: map[string]store.Provenance{
		"osv": {
			Ecosystems: []string{"Alpine:v3.19"},
			DataAsOf:   daysAgo(200),
			KeyAsOf:    map[string]time.Time{"Alpine:v3.19": since},
			Frozen:     map[string]time.Time{"Alpine:v3.19": since},
		},
	}})
	out, errOut, code := scanImage(t, db, alpine319Files(), Options{DBMaxAge: 24 * time.Hour, Output: "json"})
	if code != 2 {
		t.Fatalf("Run = %d, want 2\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	want := "error: vulnerability data for Alpine:v3.19 is 100 days old (osv, frozen since " + ymd(since) + ")"
	if !strings.Contains(errOut, want) {
		t.Errorf("stderr does not judge the carried key by its freeze\nwant: %s\ngot:\n%s", want, errOut)
	}
	if strings.Contains(errOut, "200 days old") {
		t.Errorf("stderr judged the frozen key by the provider's stalest live archive:\n%s", errOut)
	}

	// Without the gate, coverage[] dates the frozen key by its freeze too.
	out, _, code = scanImage(t, db, alpine319Files(), Options{Output: "json"})
	if code == 2 {
		t.Fatalf("Run without the gate = 2: %s", out)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("stdout is not one JSON document: %v", err)
	}
	var recs []d111Coverage
	if err := json.Unmarshal(raw["coverage"], &recs); err != nil || len(recs) != 1 {
		t.Fatalf("coverage = %s (%v), want one record", raw["coverage"], err)
	}
	if recs[0].DataAsOf != ymd(since) || recs[0].FrozenSince != ymd(since) {
		t.Errorf("coverage[0] = %+v, want dataAsOf and frozenSince both %s", recs[0], ymd(since))
	}
}
