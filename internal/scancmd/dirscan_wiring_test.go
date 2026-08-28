package scancmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The end-to-end shape of D26: a polyglot directory reports BOTH ecosystems'
// findings, and names what it did not read.
//
// Before this, the same directory reported the Go packages, said
// "0 not evaluated", and exited 0 while the npm and PyPI findings went
// unmentioned — 3 findings where the same packages as an SBOM gave 27.
// nlChar is a newline, assembled rather than typed: a literal escape written
// into this file by a generator collapses into the byte it denotes, which is
// the hazard CLAUDE.md records and which fired four times in the session that
// added D38.
var nlChar = string(rune(10))

func TestRun_DirectoryScanReadsLockfilesAndDisclosesTheRest(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "go.mod",
		"module example.com/poly\n\ngo 1.22\n\nrequire example.com/critical v1.0.0\n")
	writeManifest(t, dir, "package-lock.json",
		`{"lockfileVersion":3,"packages":{"":{"version":"1.0.0"},`+
			`"node_modules/example.com/medium":{"version":"1.0.0"}}}`)
	writeManifest(t, dir, "requirements.txt", "Django==3.2.12\nflask>=2.0\n")

	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-critical", pkg: "critical", fixed: "2.0.0", vectors: []string{vecCritical}},
		{id: "GHSA-medium", pkg: "medium", fixed: "2.0.0", vectors: []string{vecMedium}},
	})
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, "dir:"+dir, Options{}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0; stderr: %s", code, errOut.String())
	}

	// D38: requirements.txt is read now, so what must be disclosed is the LINE
	// it could not use, not the file. Asserted on the rendered triple rather
	// than on "requirements.txt" or "flask" alone: both strings appear in paths
	// the scan prints, so a bare Contains would pass from the wrong line.
	if !strings.Contains(errOut.String(), "not pinned: requirements.txt: flask>=2.0 (") {
		t.Errorf("the scan did not name the requirement it could not use:\n%s", errOut.String())
	}
	// ...and the reason has to travel with it. A reader told only that
	// something was skipped cannot act on it.
	if !strings.Contains(errOut.String(), "not pinned to one version") {
		t.Errorf("the disclosure carries no reason:\n%s", errOut.String())
	}
	// The pinned line became a package. Without this, the two assertions above
	// pass for a parser that refuses every line — which is the behaviour D38
	// replaced, not the one it introduced.
	// The pinned line became a package and reached the matcher. Without this,
	// the two assertions above pass for a parser that refuses every line —
	// which is the behaviour D38 replaced, not the one it introduced.
	//
	// Asserted on stdout, not stderr: results go to stdout and diagnostics to
	// stderr, and reaching for the wrong stream is how an assertion passes or
	// fails for a reason unrelated to what it tests.
	//
	// Four components, not three: go.mod's module, package-lock's package, and
	// BOTH requirement lines. An unpinned requirement is still a component the
	// scan saw and did not evaluate, which is what makes it show up in the
	// "not evaluated" figure rather than vanishing.
	if !strings.Contains(out.String(), "4 component(s) seen") {
		t.Errorf("want four components — go.mod, package-lock.json and both requirement lines:\n%s", out.String())
	}
	// Named, not merely counted. This database covers only Go, so the pinned
	// requirement lands as a coverage skip — which is the proof it reached the
	// matcher at all rather than being dropped by the cataloger.
	if !strings.Contains(out.String(), `Django 3.2.12: ecosystem "PyPI"`) {
		t.Errorf("the pinned requirement did not reach the matcher as a PyPI package:\n%s", out.String())
	}
	// Both ecosystems reached the matcher, which is the half that removes the
	// silent miss. The Go one alone would have passed before this slice.
	for _, want := range []string{"example.com/critical", "example.com/medium"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("%s is absent from the report — the scan is still reading one "+
				"manifest and ignoring the other:\n%s", want, out.String())
		}
	}
	// Diagnostics stay off stdout so `--output json | jq` keeps working.
	if strings.Contains(out.String(), "not read:") {
		t.Errorf("the disclosure leaked onto stdout:\n%s", out.String())
	}
}

// The D23 caveat is about go.mod specifically, so a directory without one must
// not claim anything about it — and the count it prints must be go.mod's own,
// not the merged total across every manifest.
func TestRun_TheGoModCaveatIsAccurateOrAbsent(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{})
	lock := `{"lockfileVersion":3,"packages":{"":{"version":"1.0.0"},` +
		`"node_modules/example.com/medium":{"version":"1.0.0"}}}`

	t.Run("no go.mod, no claim about one", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, dir, "package-lock.json", lock)
		var out, errOut bytes.Buffer
		// The exit code is deliberately not asserted here. buildMatrixDB covers
		// only "Go", so the npm package this fixture catalogs is correctly
		// reported as unevaluated and the scan exits 2 (D20) — which is the
		// right answer for this database and says nothing about the subject.
		// What matters is that the scan does not claim anything about a go.mod
		// that is not there.
		Run(context.Background(), db, "dir:"+dir, Options{}, &out, &errOut)
		// Matched on the caveat's own opening, not on the bare string "go.mod".
		// t.TempDir() derives its path from the test's name, which contains
		// "go.mod", so a bare Contains passes from the scanned path echoed in
		// the first stderr line — the assertion would hold whether or not the
		// caveat was printed. Exactly the wrong-column trap CLAUDE.md records,
		// and it caught this test on its first run.
		if strings.Contains(errOut.String(), "go.mod names ") {
			t.Errorf("the scan printed the go.mod caveat for a directory that has "+
				"none:\n%s", errOut.String())
		}
	})

	t.Run("the count is go.mod's own, not the merged total", func(t *testing.T) {
		dir := t.TempDir()
		// Two modules in go.mod, one package in the lockfile. Printing the
		// merged total would say 3; printing go.mod's own says 2. With equal
		// counts this assertion could not tell the two apart.
		writeManifest(t, dir, "go.mod", "module example.com/poly\n\ngo 1.22\n\n"+
			"require (\n\texample.com/critical v1.0.0\n\texample.com/other v1.0.0\n)\n")
		writeManifest(t, dir, "package-lock.json", lock)
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), db, "dir:"+dir, Options{}, &out, &errOut); code != 0 {
			t.Fatalf("Run = %d, want 0; stderr: %s", code, errOut.String())
		}
		if !strings.Contains(errOut.String(), "go.mod names 2 module(s)") {
			t.Errorf("the go.mod caveat does not carry go.mod's own count "+
				"(2 modules, not the merged 3):\n%s", errOut.String())
		}
	})
}

// A manifest that was found and could not be read must reach the exit code.
//
// Before this, the scan printed "not read: ..." and exited 0 — no gate saw it,
// because an unreadable manifest yields no packages and so contributes nothing
// to Components or to the skip counters that Trustworthy() and
// --fail-on-incomplete read. That is D26's own blind spot one level up, and it
// was a regression: before this cataloger existed, gomod.Parse's error on an
// unparseable go.mod returned 2.
func TestRun_AnUnreadableManifestReachesTheExitCode(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-critical", pkg: "critical", fixed: "2.0.0", vectors: []string{vecCritical}},
	})
	const truncated = `{"lockfileVersion":3, "packages": `
	goodMod := "module example.com/poly\n\ngo 1.22\n\nrequire example.com/critical v1.0.0\n"

	t.Run("nothing readable at all is exit 2, with or without the flag", func(t *testing.T) {
		for _, opts := range []Options{{}, {FailOnIncomplete: true}} {
			dir := t.TempDir()
			writeManifest(t, dir, "package-lock.json", truncated)
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), db, "dir:"+dir, opts, &out, &errOut); code != 2 {
				t.Errorf("Run(%+v) = %d, want 2 — a directory whose only manifest "+
					"could not be read has not produced a result worth acting on;"+
					"\nstdout: %s\nstderr: %s", opts, code, out.String(), errOut.String())
			}
		}
	})

	// A partial failure is a normal incomplete scan: opt-in, so one bad
	// lockfile in a large tree does not fail every CI job that has one.
	t.Run("a partial failure is opt-in", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, dir, "go.mod", goodMod)
		writeManifest(t, dir, "package-lock.json", truncated)

		var out, errOut bytes.Buffer
		// 0, not 2: without --fail-on-incomplete a partial failure is a normal
		// scan, and Options{} sets no --fail-on either, so the critical finding
		// does not trip anything on its own (D21).
		if code := Run(context.Background(), db, "dir:"+dir, Options{}, &out, &errOut); code != 0 {
			t.Errorf("Run = %d, want 0 — one unreadable manifest must not fail a "+
				"scan that did not ask about coverage; stderr: %s", code, errOut.String())
		}
		// The Go package was still cataloged, so the failure did not cost the
		// rest of the tree.
		if !strings.Contains(out.String(), "example.com/critical") {
			t.Errorf("one unreadable manifest lost the readable one's packages:\n%s",
				out.String())
		}

		out.Reset()
		errOut.Reset()
		if code := Run(context.Background(), db, "dir:"+dir,
			Options{FailOnIncomplete: true}, &out, &errOut); code != 2 {
			t.Errorf("Run(--fail-on-incomplete) = %d, want 2 — an unreadable "+
				"manifest is exactly the partial coverage that flag asks about; "+
				"stderr: %s", code, errOut.String())
		}
	})

	// D38 removed the premise this subtest used to rest on: requirements.txt is
	// no longer unread, so "we chose not to look" is not a state it can be in.
	// What replaces it is the distinction D36 introduced, now reachable from a
	// real file rather than a hand-built Skipped.
	t.Run("an unpinned requirement is the caller's to fix", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, dir, "go.mod", goodMod)
		writeManifest(t, dir, "requirements.txt", "flask>=2.0"+nlChar)
		var out, errOut bytes.Buffer
		// The broad gate fires: something went unevaluated.
		if code := Run(context.Background(), db, "dir:"+dir,
			Options{FailOnIncomplete: true}, &out, &errOut); code != 2 {
			t.Errorf("Run(--fail-on-incomplete) = %d, want 2; stderr: %s", code, errOut.String())
		}
		out.Reset()
		errOut.Reset()
		// ...and so does the narrow one, because pinning it is an action the
		// person running the scan can actually take. This is the case D36's
		// scope exists for, and it was silent until the cataloger's own skips
		// were counted into it.
		if code := Run(context.Background(), db, "dir:"+dir,
			Options{FailOnIncompleteTarget: true}, &out, &errOut); code != 2 {
			t.Errorf("Run(--fail-on-incomplete=target) = %d, want 2 — an unpinned "+
				"requirement is the caller's own file; stderr: %s", code, errOut.String())
		}
	})

	// The contrast that makes the assertion above mean something. A PINNED
	// requirement is evaluated; if it goes unevaluated anyway it is because
	// this database does not cover PyPI, which is assay's coverage and not the
	// caller's data — so the broad gate fires and the narrow one must not.
	t.Run("an uncovered ecosystem is not the caller's to fix", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, dir, "go.mod", goodMod)
		writeManifest(t, dir, "requirements.txt", "Django==3.2.12"+nlChar)
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), db, "dir:"+dir,
			Options{FailOnIncompleteTarget: true}, &out, &errOut); code != 0 {
			t.Errorf("Run(--fail-on-incomplete=target) = %d, want 0 — the requirement "+
				"is pinned; what is missing is PyPI coverage, which the caller "+
				"cannot pin their way out of; stderr: %s", code, errOut.String())
		}
	})
}

// D103's local/git/malformed split, driven end to end through the same
// --fail-on-incomplete=target gate TestRun_AnUnreadableManifestReachesTheExitCode
// checks for requirements.txt. A pnpm workspace member is nothing to
// evaluate at all (clean, even under the narrow gate); a git dependency is a
// real package the scan could not reach, which is exactly the caller's own
// file to fix.
func TestRun_PnpmLocalVersusGitSkipsReachTheTargetGateDifferently(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{})

	t.Run("a local workspace member is clean, even under the narrow gate", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, dir, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n"+
			"  '@fixture-scope/workspace-only@0.0.0-use.local':\n"+
			"    resolution: {directory: packages/workspace-only, type: directory}\n")

		var out, errOut bytes.Buffer
		if code := Run(context.Background(), db, "dir:"+dir,
			Options{FailOnIncompleteTarget: true}, &out, &errOut); code != 0 {
			t.Errorf("Run(--fail-on-incomplete=target) = %d, want 0 — a workspace member "+
				"is nothing to evaluate, not a gap; stderr: %s", code, errOut.String())
		}
		// Still shown, even though it does not gate.
		if !strings.Contains(errOut.String(), "workspace-only") {
			t.Errorf("the workspace member was not disclosed at all:\n%s", errOut.String())
		}
	})

	t.Run("a git dependency is the caller's own file to fix", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, dir, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n"+
			"  forked-only-dep@0.0.0:\n"+
			"    resolution: {type: git, repo: 'https://github.com/acme-org/forked-only-dep', commit: deadbeef1234}\n")

		var out, errOut bytes.Buffer
		if code := Run(context.Background(), db, "dir:"+dir,
			Options{FailOnIncompleteTarget: true}, &out, &errOut); code != 2 {
			t.Errorf("Run(--fail-on-incomplete=target) = %d, want 2 — a git dependency is "+
				"a real package this scan could not reach; stderr: %s", code, errOut.String())
		}
		if !strings.Contains(errOut.String(), "forked-only-dep") {
			t.Errorf("the git dependency was not disclosed:\n%s", errOut.String())
		}

		// The broad --fail-on-incomplete gate must fire too - narrowing to
		// =target only restricts WHICH incompleteness gates, not whether the
		// broad one still does.
		out.Reset()
		errOut.Reset()
		if code := Run(context.Background(), db, "dir:"+dir,
			Options{FailOnIncomplete: true}, &out, &errOut); code != 2 {
			t.Errorf("Run(--fail-on-incomplete) = %d, want 2; stderr: %s", code, errOut.String())
		}
	})
}
