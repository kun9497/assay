package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// dbBuiltAgo writes a database whose Meta.BuiltAt is `ago` before now and
// whose one provider's data is current, so the only thing old about it is
// when it was assembled -- the case D139 warns about.
func dbBuiltAgo(t *testing.T, ago time.Duration) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt: time.Now().Add(-ago).UTC(),
		Providers: map[string]store.Provenance{
			"osv": {Ecosystems: []string{"Go"}, DataAsOf: time.Now().Add(-ago).UTC()},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func goSBOM(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(p, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5",`+
		`"components":[{"type":"library","name":"example.com/x","version":"1.0.0",`+
		`"purl":"pkg:golang/example.com/x@1.0.0"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// D139: a database not refreshed for more than a week says so, on stderr,
// on every scan -- without changing the exit code or a byte of stdout. The
// published database is rebuilt every night, so a week-old one means the
// caller's `db update` stopped running, or the publish did; either way the
// result is quietly missing a week of advisories, and before this nothing
// said so unless the caller had chosen a --db-max-age.
func TestRun_WarnsWhenTheDatabaseIsMoreThanAWeekOld(t *testing.T) {
	path := dbBuiltAgo(t, 10*24*time.Hour)
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), path, goSBOM(t), Options{Output: "json"}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0 -- the warning is not a gate\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "warning: this database was built 10 days ago") {
		t.Errorf("stderr does not warn about the database's age:\n%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "assay db update") {
		t.Errorf("the warning does not say what to run:\n%s", errOut.String())
	}
	// stdout is the JSON report and nothing else, so `| jq` is untouched.
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Errorf("stdout is not a clean JSON report (%v): %s", err, out.String())
	}
	if strings.Contains(out.String(), "database was built") {
		t.Errorf("the warning reached stdout, which must stay a clean report:\n%s", out.String())
	}
}

func TestRun_NoWarningForADatabaseBuiltThisWeek(t *testing.T) {
	path := dbBuiltAgo(t, 2*24*time.Hour)
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), path, goSBOM(t), Options{}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0\nstderr: %s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "database was built") {
		t.Errorf("a two-day-old database was warned about:\n%s", errOut.String())
	}
}

// The boundary: seven days is the limit, and a database exactly at it is
// not yet stale; one a day past it is.
func TestStaleDBWarning_Boundary(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		age  time.Duration
		warn bool
	}{
		{7 * 24 * time.Hour, false},
		{7*24*time.Hour + time.Hour, true},
		{0, false},
	} {
		var buf bytes.Buffer
		warnIfStale(store.Meta{BuiltAt: now.Add(-c.age)}, now, &buf)
		if got := buf.Len() > 0; got != c.warn {
			t.Errorf("age %v: warned = %v, want %v (%q)", c.age, got, c.warn, buf.String())
		}
	}
	// A database that never recorded when it was built is not called old:
	// D17's discipline says silence is not evidence either way, and this
	// is a warning, not the --db-max-age gate that refuses on it.
	var buf bytes.Buffer
	warnIfStale(store.Meta{}, now, &buf)
	if buf.Len() != 0 {
		t.Errorf("an undated database was warned about: %q", buf.String())
	}
}

// D139's central choice: the warning reads BuiltAt, never the upstream
// data's age. A database built today over a dead feed (the live artifact's
// dataAsOf is 2025-03-06, Amazon ALAS) is current and must not warn;
// --db-max-age is where data age is judged.
func TestRun_NoWarningForAFreshBuildOverOldUpstreamData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt: time.Now().Add(-time.Hour).UTC(),
		Providers: map[string]store.Provenance{
			"osv": {Ecosystems: []string{"Go"}, DataAsOf: time.Now().AddDate(-1, 0, 0).UTC()},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), path, goSBOM(t), Options{}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0\nstderr: %s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "database was built") {
		t.Errorf("a database built an hour ago was warned about for its year-old upstream data:\n%s", errOut.String())
	}
}
