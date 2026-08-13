package scancmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

func day(n int) time.Time {
	return time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -n)
}

var now = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

func metaWith(p map[string]time.Time) store.Meta {
	m := store.Meta{Providers: map[string]store.Provenance{}}
	for name, asOf := range p {
		m.Providers[name] = store.Provenance{DataAsOf: asOf}
	}
	return m
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
	if code := checkDBAge(m, 48*time.Hour, now, &buf); code != 2 {
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
	if code := checkDBAge(m, 48*time.Hour, now, &buf); code != 0 {
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
	if code := checkDBAge(m, 30*24*time.Hour, now, &buf); code != 2 {
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
		if code := checkDBAge(m, max, now, &buf); code != 0 {
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
		"osv": {DataAsOf: exactly},
	}}
	if code := checkDBAge(m, 48*time.Hour, now, &buf); code != 0 {
		t.Errorf("checkDBAge at exactly the limit = %d, want 0:\n%s", code, buf.String())
	}
	// One second past it is not.
	if code := checkDBAge(m, 48*time.Hour-time.Second, now, &buf); code != 2 {
		t.Errorf("checkDBAge one second past the limit = %d, want 2", code)
	}
}

// TestCheckDBAge_NoProvidersIsNotThisCheckSFailure. A database with none cannot
// serve a scan for other reasons and D20's coverage check says so; failing here
// too would report the wrong cause and send the reader after a freshness
// problem they do not have.
func TestCheckDBAge_NoProvidersIsNotThisChecksFailure(t *testing.T) {
	var buf bytes.Buffer
	if code := checkDBAge(store.Meta{}, time.Hour, now, &buf); code != 0 {
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
	if code := checkDBAge(m, 48*time.Hour, now, &buf); code != 0 {
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
	first, _, _ := oldestProvider(m)
	for i := 0; i < 20; i++ {
		got, name, _ := oldestProvider(m)
		if !got.Equal(first) || name != "alpha" {
			t.Fatalf("oldestProvider gave %q on run %d; want alpha every time", name, i)
		}
	}
}
