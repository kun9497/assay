package scancmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

func day(n int) time.Time {
	return time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -n)
}

var now = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

// metaWith gives each provider one ecosystem key of its own, named after it,
// so a test can put every provider in scope with allKeys (D113) and exercise
// D59's rules exactly as they read before the scope existed.
func metaWith(p map[string]time.Time) store.Meta {
	m := store.Meta{Providers: map[string]store.Provenance{}}
	for name, asOf := range p {
		m.Providers[name] = store.Provenance{Ecosystems: []string{"eco-" + name}, DataAsOf: asOf}
	}
	return m
}

// allKeys is every key any provider in m declares: a scan whose inventory
// touches every provider, which is the database-wide check D59 described.
func allKeys(m store.Meta) []string {
	var keys []string
	for _, p := range m.Providers {
		keys = append(keys, p.Ecosystems...)
	}
	return keys
}

// TestCheckDBAge_UsesTheOldestProvider is the property that makes the check
// mean anything. A database is only as fresh as its stalest source, and taking
// the newest would let one daily provider vouch for another that stopped
// updating months ago — which is exactly the failure this flag exists to catch.
func TestCheckDBAge_UsesTheOldestProvider(t *testing.T) {
	var buf bytes.Buffer
	m := metaWith(map[string]time.Time{
		"osv":     day(0), // fetched today
		"redhat":  day(0),
		"stalled": day(90), // three months behind
	})
	if code := checkDBAge(m, allKeys(m), 48*time.Hour, now, &buf); code != 2 {
		t.Errorf("checkDBAge = %d, want 2 — one provider is 90 days old", code)
	}
	// The message has to NAME the stale provider. "the data is old" leaves the
	// reader to work out which feed died.
	if !strings.Contains(buf.String(), "stalled") {
		t.Errorf("the error does not name the stale provider:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "90 days") {
		t.Errorf("the error does not say how old:\n%s", buf.String())
	}
}

// TestCheckDBAge_PassesWhenFresh is the other half. A check that always
// refused would be caught by nothing else here: every other test asserts a
// refusal.
func TestCheckDBAge_PassesWhenFresh(t *testing.T) {
	var buf bytes.Buffer
	m := metaWith(map[string]time.Time{"osv": day(1), "redhat": day(0)})
	if code := checkDBAge(m, allKeys(m), 48*time.Hour, now, &buf); code != 0 {
		t.Errorf("checkDBAge = %d, want 0 — the oldest provider is a day old:\n%s",
			code, buf.String())
	}
	if buf.Len() != 0 {
		t.Errorf("a passing check wrote to stderr:\n%s", buf.String())
	}
}

// TestCheckDBAge_UnknownAgeIsRefused. D17's discipline applied to time: a
// provider that could not say when its data was current has not said it is
// fresh. Passing it would let exactly the stale database this exists to catch
// through, because the provider whose feed died is also the one least likely to
// report a date.
func TestCheckDBAge_UnknownAgeIsRefused(t *testing.T) {
	var buf bytes.Buffer
	m := metaWith(map[string]time.Time{
		"osv":       day(0),
		"undated":   {}, // zero DataAsOf
		"alsoUnset": {},
	})
	if code := checkDBAge(m, allKeys(m), 30*24*time.Hour, now, &buf); code != 2 {
		t.Errorf("checkDBAge = %d, want 2 — two providers recorded no date", code)
	}
	s := buf.String()
	for _, want := range []string{"undated", "alsoUnset"} {
		if !strings.Contains(s, want) {
			t.Errorf("the error does not name %q:\n%s", want, s)
		}
	}
	// And it says what to do. An error that only states a fact leaves the
	// reader without a next step.
	if !strings.Contains(s, "db update") {
		t.Errorf("the error suggests no remedy:\n%s", s)
	}
}

// TestCheckDBAge_OffByDefault. Zero disables the check, and every scan that
// does not pass the flag goes through here — so a check that ran anyway would
// change the behaviour of every existing caller.
func TestCheckDBAge_OffByDefault(t *testing.T) {
	var buf bytes.Buffer
	// Deliberately ancient AND undated: neither may matter when the flag is off.
	m := metaWith(map[string]time.Time{"ancient": day(3650), "undated": {}})
	for _, max := range []time.Duration{0, -time.Hour} {
		buf.Reset()
		if code := checkDBAge(m, allKeys(m), max, now, &buf); code != 0 {
			t.Errorf("checkDBAge(max=%v) = %d, want 0 — the check is off", max, code)
		}
		if buf.Len() != 0 {
			t.Errorf("checkDBAge(max=%v) wrote to stderr with the check off:\n%s", max, buf.String())
		}
	}
}

// TestCheckDBAge_BoundaryIsInclusive. Exactly at the limit is allowed:
// --db-max-age=24h on a database refreshed every 24 hours must not fail half
// the time on a race with the clock.
func TestCheckDBAge_BoundaryIsInclusive(t *testing.T) {
	var buf bytes.Buffer
	exactly := now.Add(-48 * time.Hour)
	m := store.Meta{Providers: map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go"}, DataAsOf: exactly},
	}}
	if code := checkDBAge(m, allKeys(m), 48*time.Hour, now, &buf); code != 0 {
		t.Errorf("checkDBAge at exactly the limit = %d, want 0:\n%s", code, buf.String())
	}
	// One second past it is not.
	if code := checkDBAge(m, allKeys(m), 48*time.Hour-time.Second, now, &buf); code != 2 {
		t.Errorf("checkDBAge one second past the limit = %d, want 2", code)
	}
}

// TestCheckDBAge_NoProvidersIsNotThisCheckSFailure. A database with none cannot
// serve a scan for other reasons and D20's coverage check says so; failing here
// too would report the wrong cause and send the reader after a freshness
// problem they do not have.
func TestCheckDBAge_NoProvidersIsNotThisChecksFailure(t *testing.T) {
	var buf bytes.Buffer
	if code := checkDBAge(store.Meta{}, nil, time.Hour, now, &buf); code != 0 {
		t.Errorf("checkDBAge on an empty database = %d, want 0 — D20 owns this failure", code)
	}
}

// TestCheckDBAge_IgnoresRatingsAndEnrichment. Both are additive: stale NVD
// means some findings carry no score, which the report already says (D17), and
// stale KISA prose cannot move a verdict (D3). Only the advisories decide
// whether a package is reported affected, so only their age can make a clean
// result untrustworthy — and folding them in would fail builds over prose.
func TestCheckDBAge_IgnoresRatingsAndEnrichment(t *testing.T) {
	var buf bytes.Buffer
	m := metaWith(map[string]time.Time{"osv": day(0)})
	m.Ratings = map[string]store.Provenance{"NVD": {DataAsOf: day(400)}}
	m.Enrichment = map[string]store.Provenance{"KISA": {DataAsOf: day(400)}}
	if code := checkDBAge(m, allKeys(m), 48*time.Hour, now, &buf); code != 0 {
		t.Errorf("checkDBAge = %d, want 0 — ratings and enrichment age must not "+
			"fail a scan:\n%s", code, buf.String())
	}
}

// TestRoundAge renders an age the way someone reads one. "1583h24m" is a number
// the reader has to convert before they can act on it, and this output exists
// to be acted on.
func TestRoundAge(t *testing.T) {
	for _, tt := range []struct {
		in   time.Duration
		want string
	}{
		{90 * 24 * time.Hour, "90 days"},
		{24 * time.Hour, "1 day"},
		{47 * time.Hour, "1 day"},
		{23 * time.Hour, "23h0m0s"},
		{90*time.Minute + 30*time.Second, "1h31m0s"},
	} {
		if got := roundAge(tt.in); got != tt.want {
			t.Errorf("roundAge(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestOldestProvider_IsDeterministic. Two providers can share a timestamp, and
// which one the error names must not depend on map iteration order — design
// goal #3 reaches error messages too, or a flaky CI log is the result.
func TestOldestProvider_IsDeterministic(t *testing.T) {
	m := metaWith(map[string]time.Time{
		"zebra": day(10), "alpha": day(10), "middle": day(10),
	})
	first := oldestProvider(m, allKeys(m)).at
	for i := 0; i < 20; i++ {
		f := oldestProvider(m, allKeys(m))
		if !f.at.Equal(first) || f.provider != "alpha" {
			t.Fatalf("oldestProvider gave %q on run %d; want alpha every time", f.provider, i)
		}
	}
}

// TestRun_DBMaxAgeIsActuallyConsulted is the wiring, and nothing else held it:
// a mutation disabling the call in Run left every test above green, because all
// of them exercise checkDBAge directly and none of them is a scan.
//
// Sixth time in this project that a helper was covered and its caller was not.
func TestRun_DBMaxAgeIsActuallyConsulted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately ancient, and coverage declared so that D20 is not what
	// fails: the refusal under test has to be the age one.
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go"}, DataAsOf: time.Now().AddDate(0, 0, -400)},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5",`+
		`"components":[{"type":"library","name":"example.com/x","version":"1.0.0",`+
		`"purl":"pkg:golang/example.com/x@1.0.0"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := Run(context.Background(), path, sbom,
		Options{DBMaxAge: 48 * time.Hour}, &out, &errOut)
	if code != 2 {
		t.Fatalf("Run = %d, want 2 — the database is 400 days old\nstdout: %s\nstderr: %s",
			code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "db-max-age") {
		t.Errorf("stderr does not mention the flag that refused the scan:\n%s", errOut.String())
	}
	// And nothing was written to stdout: a verdict printed before the refusal
	// would be a result from data the next line calls untrustworthy.
	if out.Len() != 0 {
		t.Errorf("a refused scan wrote a report to stdout:\n%s", out.String())
	}
}

// TestRun_WithoutDBMaxAgeAnAncientDatabaseStillScans. The flag is off by
// default, and every existing caller goes through this path — a check that ran
// anyway would change all of them.
func TestRun_WithoutDBMaxAgeAnAncientDatabaseStillScans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go"}, DataAsOf: time.Now().AddDate(0, 0, -400)},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5",`+
		`"components":[{"type":"library","name":"example.com/x","version":"1.0.0",`+
		`"purl":"pkg:golang/example.com/x@1.0.0"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), path, sbom, Options{}, &out, &errOut); code != 0 {
		t.Errorf("Run = %d, want 0 — the check is off\nstderr: %s", code, errOut.String())
	}
}

// TestCheckDBAge_LiveWordingIsUnchanged pins D59's refusal byte for byte: D113
// added a frozen variant beside it, and a caller grepping CI logs for the old
// line must still find it.
func TestCheckDBAge_LiveWordingIsUnchanged(t *testing.T) {
	var buf bytes.Buffer
	m := metaWith(map[string]time.Time{"stalled": day(90)})
	if code := checkDBAge(m, allKeys(m), 24*time.Hour, now, &buf); code != 2 {
		t.Fatalf("checkDBAge = %d, want 2", code)
	}
	const want = "error: vulnerability data is 90 days old (stalled, as of 2026-05-15), " +
		"past the 24h0m0s allowed by --db-max-age\n" +
		"  run `assay db update`; this result would not be trustworthy\n"
	if buf.String() != want {
		t.Errorf("stderr =\n%q\nwant\n%q", buf.String(), want)
	}
}

// TestCheckDBAge_AFrozenKeyOutsideTheInventoryIsNotMeasured. The freeze is a
// fact about one key; a scan that holds a provider's live key and not its
// frozen one reads nothing from the freeze, so the freeze does not age it.
func TestCheckDBAge_AFrozenKeyOutsideTheInventoryIsNotMeasured(t *testing.T) {
	var buf bytes.Buffer
	m := store.Meta{Providers: map[string]store.Provenance{"osv": {
		Ecosystems: []string{"Alpine:v3.18", "Alpine:v3.19"},
		DataAsOf:   day(0),
		Frozen:     map[string]time.Time{"Alpine:v3.18": day(200)},
	}}}
	if code := checkDBAge(m, []string{"Alpine:v3.19"}, 48*time.Hour, now, &buf); code != 0 {
		t.Errorf("checkDBAge(v3.19 only) = %d, want 0 — the frozen key is not scanned:\n%s", code, buf.String())
	}
	buf.Reset()
	if code := checkDBAge(m, []string{"Alpine:v3.18", "Alpine:v3.19"}, 48*time.Hour, now, &buf); code != 2 {
		t.Errorf("checkDBAge(both keys) = %d, want 2 — v3.18 has been frozen 200 days", code)
	}
	const want = "error: vulnerability data for Alpine:v3.18 is 200 days old (osv, frozen since 2026-01-25), " +
		"past the 48h0m0s allowed by --db-max-age\n"
	if !strings.HasPrefix(buf.String(), want) {
		t.Errorf("stderr =\n%q\nwant it to start with\n%q", buf.String(), want)
	}
	// The remedy differs from the live case: db update cannot refresh a key
	// its upstream stopped publishing, so saying "run db update" would send
	// the reader after a fix that does not exist.
	if strings.Contains(buf.String(), "this result would not be trustworthy") {
		t.Errorf("a frozen-key refusal gives the live-key remedy:\n%s", buf.String())
	}
}

// TestCheckDBAge_OldestAcrossTheSetWins: a frozen key in one provider and a
// stale provider beside it — whichever is older names the refusal, so a
// freeze cannot hide a dead feed or the other way round.
func TestCheckDBAge_OldestAcrossTheSetWins(t *testing.T) {
	m := store.Meta{Providers: map[string]store.Provenance{
		"osv":    {Ecosystems: []string{"npm"}, DataAsOf: day(0), Frozen: map[string]time.Time{"npm": day(30)}},
		"redhat": {Ecosystems: []string{"Red Hat:9"}, DataAsOf: day(60)},
	}}
	f := oldestProvider(m, []string{"Red Hat:9", "npm"})
	if f.provider != "redhat" || f.frozenKey != "" || !f.at.Equal(day(60)) {
		t.Errorf("floor = %+v, want redhat's own 60-day-old date", f)
	}
	m.Providers["redhat"] = store.Provenance{Ecosystems: []string{"Red Hat:9"}, DataAsOf: day(10)}
	f = oldestProvider(m, []string{"Red Hat:9", "npm"})
	if f.provider != "osv" || f.frozenKey != "npm" || !f.at.Equal(day(30)) {
		t.Errorf("floor = %+v, want osv's npm freeze, 30 days old", f)
	}
}

// TestCheckDBAge_AFreezeWithNoDateIsAnUnknownAge. A frozen key whose freeze
// date was never recorded has no age, and D59 refuses an unknown age rather
// than read it as the provider's fresh one.
func TestCheckDBAge_AFreezeWithNoDateIsAnUnknownAge(t *testing.T) {
	var buf bytes.Buffer
	m := store.Meta{Providers: map[string]store.Provenance{"osv": {
		Ecosystems: []string{"Debian:11"},
		DataAsOf:   day(0),
		Frozen:     map[string]time.Time{"Debian:11": {}},
	}}}
	if code := checkDBAge(m, []string{"Debian:11"}, 48*time.Hour, now, &buf); code != 2 {
		t.Errorf("checkDBAge = %d, want 2 — the frozen key's age was not recorded", code)
	}
	if !strings.Contains(buf.String(), "osv did not record when its data was current") {
		t.Errorf("the refusal does not name the provider:\n%s", buf.String())
	}
}

// TestCheckDBAge_NoKeyDeclaredIsNotThisChecksFailure. Providers exist but none
// declares a key the inventory holds: nothing to measure, and D20 already says
// the key is uncovered.
func TestCheckDBAge_NoKeyDeclaredIsNotThisChecksFailure(t *testing.T) {
	var buf bytes.Buffer
	m := metaWith(map[string]time.Time{"ancient": day(3650), "undated": {}})
	for _, keys := range [][]string{nil, {"eco-nobody"}} {
		buf.Reset()
		if code := checkDBAge(m, keys, time.Hour, now, &buf); code != 0 || buf.Len() != 0 {
			t.Errorf("checkDBAge(keys=%v) = %d, want 0 and silence:\n%s", keys, code, buf.String())
		}
	}
}

// TestCheckRatingAge covers the rating gate's branches directly; the caller
// tests in dbage_scope_test.go hold that Run consults it.
func TestCheckRatingAge(t *testing.T) {
	ratings := func(p map[string]time.Time) store.Meta {
		m := store.Meta{Ratings: map[string]store.Provenance{}}
		for n, at := range p {
			m.Ratings[n] = store.Provenance{DataAsOf: at}
		}
		return m
	}
	for _, tc := range []struct {
		name string
		m    store.Meta
		max  time.Duration
		code int
		want string
	}{
		{"off", ratings(map[string]time.Time{"NVD": day(400), "KEV": {}}), 0, 0, ""},
		{"fresh", ratings(map[string]time.Time{"NVD": day(1), "EPSS": day(0)}), 48 * time.Hour, 0, ""},
		{"stale names the oldest", ratings(map[string]time.Time{"NVD": day(90), "EPSS": day(0), "KEV": day(5)}),
			48 * time.Hour, 2,
			"error: rating data is 90 days old (NVD, as of 2026-05-15), past the 48h0m0s allowed by --db-max-rating-age\n"},
		{"undated", ratings(map[string]time.Time{"NVD": day(0), "KEV": {}}), 48 * time.Hour, 2,
			"error: --db-max-rating-age given, but KEV did not record when its data was current"},
		{"no source at all", store.Meta{}, 48 * time.Hour, 2,
			"error: --db-max-rating-age given, but this database carries no rating source"},
		// Advisory providers are not rating sources: an ancient one does not
		// trip this gate, the mirror image of D59 ignoring ratings.
		{"providers ignored", func() store.Meta {
			m := ratings(map[string]time.Time{"NVD": day(0)})
			m.Providers = map[string]store.Provenance{"osv": {Ecosystems: []string{"Go"}, DataAsOf: day(400)}}
			return m
		}(), 48 * time.Hour, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if code := checkRatingAge(tc.m, tc.max, now, &buf); code != tc.code {
				t.Errorf("checkRatingAge = %d, want %d:\n%s", code, tc.code, buf.String())
			}
			if tc.want == "" && buf.Len() != 0 {
				t.Errorf("a passing check wrote to stderr:\n%s", buf.String())
			}
			if tc.want != "" && !strings.HasPrefix(buf.String(), tc.want) {
				t.Errorf("stderr =\n%q\nwant it to start with\n%q", buf.String(), tc.want)
			}
		})
	}
}
