//go:build upstreamvectors

// This file replays npm/node-semver's own comparison fixtures against our
// comparer, alongside apk_upstream_test.go, and for the same reason: a
// hand-written table is checked only against the understanding that wrote it.
//
// Run it with:
//
//	go test -tags upstreamvectors ./internal/version/
//
// SEMVER_COMPARISONS and SEMVER_EQUALITY may point at local copies to run
// offline.
//
// # Why node-semver and not the other two candidates
//
// **golang.org/x/mod/semver was rejected as an oracle**, and the reason is a
// silent wrong answer rather than a licence or a dependency. x/mod implements
// *Go module* semver, where the leading "v" is mandatory: `IsValid("1.2.3")` is
// false. It then orders every invalid string as equal to every other, so
// `Compare("1.2.3", "1.2.4")` returns 0 where this package returns -1 — not an
// error, an ordering. OSV's SEMVER range bounds carry no "v" prefix, so that
// class is not exotic: measured over 5,546 real strings, 1,143 of them (20.6%)
// are accepted by this package and rejected by x/mod. An oracle that is silently
// wrong about a fifth of the corpus is worse than no oracle. (Importing it would
// also promote x/mod to a third direct dependency, but that was never the
// deciding objection.)
//
// **The semver specification publishes no machine-readable test data.** The
// whole semver/semver repository is 11 files and none of them is a fixture. What
// §11 does publish is three worked example chains, and those are transcribed
// into semverSpecChain below — offline, in the default suite, because eleven
// strings that have not changed since 2013 do not need a network fetch.
//
// **No language-agnostic conformance corpus exists.** There is no semver
// equivalent of JSON-Schema-Test-Suite or yaml-test-suite; every implementation
// carries its own table. Recorded here so the negative result does not have to
// be rediscovered.
package version

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	// The contents API rather than raw.githubusercontent.com, for the reason
	// apk_upstream_test.go gives: the raw host is not reliably reachable from
	// every environment this runs in.
	semverComparisonsURL = "https://api.github.com/repos/npm/node-semver/contents/" +
		"test/fixtures/comparisons.js?ref=main"
	semverEqualityURL = "https://api.github.com/repos/npm/node-semver/contents/" +
		"test/fixtures/equality.js?ref=main"
)

// fixtureRE pulls the first two quoted strings out of a `['a', 'b', opts],`
// entry. No JavaScript engine is needed because these two files are pure array
// literals of single-quoted tuples — which is NOT true of their sibling
// invalid-versions.js, which requires('../../internal/constants') and
// interpolates MAX_SAFE_INTEGER into template literals. That file is
// deliberately not replayed.
var fixtureRE = regexp.MustCompile(`^\s*\['([^']*)',\s*'([^']*)'`)

// TestSemVerAgainstNodeSemVer replays node-semver's comparisons.js: every entry
// asserts that the FIRST operand is greater than the second.
//
// node-semver is the right third-party oracle for this package specifically
// because D34 follows its loose mode — `19.03.0` normalising to `19.3.0` is
// node-semver's behaviour, not the specification's, and an oracle that did not
// share that dialect would report every leading-zero case as a divergence.
func TestSemVerAgainstNodeSemVer(t *testing.T) {
	data := loadFixture(t, "SEMVER_COMPARISONS", semverComparisonsURL)

	var c SemVer
	var total, agree int
	var mismatches, unexpectedInvalid []string

	for _, line := range strings.Split(data, lineSep) {
		m := fixtureRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		hi, lo := m[1], m[2]
		total++
		key := hi + " > " + lo

		got, err := c.Compare(hi, lo)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: error does not wrap ErrInvalid: %v", key, err)
				continue
			}
			if _, known := semverKnownDivergences[key]; !known {
				unexpectedInvalid = append(unexpectedInvalid, key)
			}
			continue
		}
		if _, known := semverKnownDivergences[key]; known {
			t.Errorf("%s: now parses, but is recorded as a known divergence. Either "+
				"the parser gained a case it should not have, or the divergence "+
				"list is stale — remove the entry deliberately.", key)
			continue
		}
		if got != 1 {
			mismatches = append(mismatches, key+" -> ours="+itoa(got))
			continue
		}
		agree++
	}

	// A fixture that shrank to nothing would otherwise pass silently. 31 today;
	// the floor leaves room for npm to prune a few without turning this test
	// into a no-op.
	if total < 25 {
		t.Fatalf("only %d comparisons parsed; the fixture's format has probably "+
			"changed and this test is no longer checking anything", total)
	}
	for _, m := range mismatches {
		t.Errorf("MISMATCH %s", m)
	}
	for _, u := range unexpectedInvalid {
		t.Errorf("UNEXPECTED ErrInvalid: %s — node-semver orders these, and refusing "+
			"to is a package we would report as unevaluable", u)
	}
	t.Logf("%d comparisons: %d agree, %d mismatch, %d known divergences",
		total, agree, len(mismatches), len(semverKnownDivergences))
}

// semverKnownDivergences lists, individually, every node-semver comparison this
// package deliberately refuses. Listed rather than counted for apk's reason: a
// tolerance hides the appearance of a NEW divergence, which would be a real
// regression.
//
// Empty today, and that is the honest state: measured 2026-08-06, all 31
// comparisons agree. It exists so that the first divergence is a decision
// somebody writes down rather than a number somebody bumps.
var semverKnownDivergences = map[string]string{}

// TestSemVerRejectsNodeSemVerLooseInput replays equality.js as a NEGATIVE
// fixture.
//
// Only 6 of its 37 entries are semver equality; the other 31 are npm's own
// input-normalisation cases — leading whitespace, an `=` prefix, embedded
// whitespace such as "v 1.2.3". node-semver accepts those because it is a
// package manager's parser taking human input. This package is a scanner's
// comparer reading machine-written advisory data, and accepting them would mean
// silently agreeing that " =v 1.2.3 " is a version.
//
// So the fixture is inverted: the entries this package must REFUSE are asserted
// by exact string. That makes the file useful as an oracle in the one direction
// it can be, rather than skipped for disagreeing.
func TestSemVerRejectsNodeSemVerLooseInput(t *testing.T) {
	data := loadFixture(t, "SEMVER_EQUALITY", semverEqualityURL)

	var c SemVer
	var checked, rejected int
	for _, line := range strings.Split(data, lineSep) {
		m := fixtureRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for _, v := range m[1:3] {
			// Only the loose shapes are under test here. A plain, already-valid
			// operand must NOT be asserted as rejected — that would invert the
			// test the moment npm reformats an entry.
			if !isLooseInput(v) {
				continue
			}
			checked++
			if _, err := c.Compare(v, "1.2.3"); err == nil {
				t.Errorf("Compare(%q, …) succeeded; this package must not accept "+
					"npm's input-normalisation forms", v)
				continue
			}
			rejected++
		}
	}
	if checked < 20 {
		t.Fatalf("only %d loose inputs found in the fixture; its format has probably "+
			"changed and this test is no longer checking anything", checked)
	}
	t.Logf("%d loose inputs, %d correctly rejected", checked, rejected)
}

// isLooseInput reports whether a fixture operand is one of npm's tolerated
// input shapes rather than a plain version: surrounding or embedded whitespace,
// or a leading '='.
func isLooseInput(v string) bool {
	return strings.TrimSpace(v) != v ||
		strings.Contains(strings.TrimSpace(v), " ") ||
		strings.HasPrefix(strings.TrimSpace(v), "=")
}

// loadFixture fetches one node-semver fixture, or reads the local copy the
// named environment variable points at.
//
// Skipping is right for a developer running offline and wrong for CI, which is
// the only place this test runs at all: a skip there turns the check into a
// no-op and still reports green.
func loadFixture(t *testing.T, envVar, url string) string {
	t.Helper()
	if p := os.Getenv(envVar); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s=%s: %v", envVar, p, err)
		}
		return string(b)
	}

	unreachable := func(format string, args ...any) {
		if os.Getenv("CI") != "" {
			t.Fatalf(format+" -- refusing to pass by skipping in CI", args...)
		}
		t.Skipf(format+"; set %s to a local copy", append(args, envVar)...)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 60 unauthenticated requests per hour per IP, shared across an Actions
	// host. A token raises it to 5,000 and costs nothing.
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		unreachable("cannot reach %s (%v)", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		unreachable("%s returned %s", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode contents response: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(payload.Content, lineSep, ""))
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return string(raw)
}
