package scancmd

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// testDBWithEOLAsOf is testDBWithEOL plus the EOL source's own provenance,
// dated asOf -- what a seed's carried catalog looks like to a ratings-only
// build with EOL_ENABLE=0 (dbcmd.Update, audit 2026-10-22 P4).
func testDBWithEOLAsOf(t *testing.T, rows []store.EOLRelease, asOf time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt:   time.Now().UTC(), // built just now: only the EOL data is old
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.19", "Go", "npm", "PyPI"}}},
		EOL:       rows,
		EOLProvenance: &store.Provenance{
			Source: "https://endoflife.date/api/v1/products/full", DataAsOf: asOf, Records: len(rows),
		},
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// The one release every test here scans: Alpine 3.19, still supported on the
// pinned day, so --fail-on-eol does not trip and the exit code isolates the
// warning.
var eolAgeRows = []store.EOLRelease{
	{DistroID: "alpine", Release: "3.19", EOLFrom: "2026-11-01", EOLLabel: "Security Support"},
}

var eolAgeToday = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

const eolAgeWarning = "end-of-life data was generated"

// A scan gated on --fail-on-eol over end-of-life data generated ten days ago
// says so on stderr, exits 0 (the warning is not a gate) and leaves stdout a
// clean JSON report. Before this, a ratings-only build with EOL_ENABLE=0
// carried its seed's catalog silently, and a release whose support ended
// after the seed's fetch read as supported.
func TestRun_FailOnEOLWarnsWhenTheEOLDataIsMoreThanAWeekOld(t *testing.T) {
	pinClock(t, eolAgeToday)
	db := testDBWithEOLAsOf(t, eolAgeRows, eolAgeToday.AddDate(0, 0, -10))

	out, errOut, code := alpine319Image(t, db, Options{FailOnEOL: true, Output: "json"})
	if code != 0 {
		t.Fatalf("Run() = %d, want 0 -- the warning is not a gate (stderr: %s)", code, errOut)
	}
	if !strings.Contains(errOut, "warning: this database's end-of-life data was generated 10 days ago (2026-10-10)") {
		t.Errorf("stderr does not warn about the end-of-life data's age:\n%s", errOut)
	}
	if !strings.Contains(errOut, "assay db update") || !strings.Contains(errOut, "EOL_ENABLE=1") {
		t.Errorf("the warning does not say what to run:\n%s", errOut)
	}
	if strings.Contains(errOut, "EOL unknown") {
		t.Errorf("stderr calls EOL unknown when the catalog answered:\n%s", errOut)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Errorf("stdout is not a clean JSON report (%v): %s", err, out)
	}
	if strings.Contains(out, eolAgeWarning) {
		t.Errorf("the warning reached stdout, which must stay a clean report:\n%s", out)
	}
}

// Without the flag nothing is gated on the catalog, so nothing is said about
// its age -- the same opt-in the "EOL unknown" disclosure has.
func TestRun_EOLAgeWarningOnlyFiresWhenTheFlagIsSet(t *testing.T) {
	pinClock(t, eolAgeToday)
	db := testDBWithEOLAsOf(t, eolAgeRows, eolAgeToday.AddDate(0, 0, -10))

	_, errOut, code := alpine319Image(t, db, Options{})
	if code != 0 {
		t.Fatalf("Run() = %d, want 0 (stderr: %s)", code, errOut)
	}
	if strings.Contains(errOut, eolAgeWarning) {
		t.Errorf("stderr warned about the end-of-life data's age with no --fail-on-eol:\n%s", errOut)
	}
}

func TestRun_NoEOLAgeWarningForDataGeneratedThisWeek(t *testing.T) {
	pinClock(t, eolAgeToday)
	db := testDBWithEOLAsOf(t, eolAgeRows, eolAgeToday.AddDate(0, 0, -2))

	_, errOut, code := alpine319Image(t, db, Options{FailOnEOL: true})
	if code != 0 {
		t.Fatalf("Run() = %d, want 0 (stderr: %s)", code, errOut)
	}
	if strings.Contains(errOut, eolAgeWarning) {
		t.Errorf("two-day-old end-of-life data was warned about:\n%s", errOut)
	}
}

// A database that carries EOL rows but no provenance for them (built before
// the source reported one) is not called old: D17's discipline, silence is
// not evidence of age, and this is a nudge rather than a gate.
func TestRun_NoEOLAgeWarningForUndatedEOLData(t *testing.T) {
	pinClock(t, eolAgeToday)
	db := testDBWithEOL(t, eolAgeRows) // EOLProvenance nil

	_, errOut, code := alpine319Image(t, db, Options{FailOnEOL: true})
	if code != 0 {
		t.Fatalf("Run() = %d, want 0 (stderr: %s)", code, errOut)
	}
	if strings.Contains(errOut, eolAgeWarning) {
		t.Errorf("undated end-of-life data was warned about:\n%s", errOut)
	}
}

// The boundary, and the shapes the caller-level tests above cannot reach in
// one fixture each: exactly seven days is not stale, an hour past it is, and a
// database with provenance but no EOL rows is the "EOL unknown" warning's
// case rather than this one.
func TestEOLAgeWarning_Boundary(t *testing.T) {
	now := eolAgeToday
	prov := func(ago time.Duration) *store.Provenance {
		return &store.Provenance{DataAsOf: now.Add(-ago)}
	}
	for _, c := range []struct {
		name string
		m    store.Meta
		flag bool
		warn bool
	}{
		{"exactly seven days", store.Meta{EOL: eolAgeRows, EOLProvenance: prov(7 * 24 * time.Hour)}, true, false},
		{"seven days and an hour", store.Meta{EOL: eolAgeRows, EOLProvenance: prov(7*24*time.Hour + time.Hour)}, true, true},
		{"flag off", store.Meta{EOL: eolAgeRows, EOLProvenance: prov(30 * 24 * time.Hour)}, false, false},
		{"zero DataAsOf", store.Meta{EOL: eolAgeRows, EOLProvenance: &store.Provenance{}}, true, false},
		{"no provenance", store.Meta{EOL: eolAgeRows}, true, false},
		{"no EOL rows", store.Meta{EOLProvenance: prov(30 * 24 * time.Hour)}, true, false},
	} {
		var buf bytes.Buffer
		warnIfEOLStale(c.m, c.flag, now, &buf)
		if got := buf.Len() > 0; got != c.warn {
			t.Errorf("%s: warned = %v, want %v (%q)", c.name, got, c.warn, buf.String())
		}
	}
}
