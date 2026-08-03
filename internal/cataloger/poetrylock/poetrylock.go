// Package poetrylock turns a poetry.lock file into the normalized package
// inventory, using nothing but the standard library.
//
// poetry.lock is TOML, and this repository takes no TOML dependency
// (CLAUDE.md: "no third-party dependencies yet" — adding one is a real
// decision this task does not get to make). A permissive, tolerant reader
// is not a safer substitute for a real TOML library either: the subset
// poetry.lock actually uses is small and rigid — a sequence of [[package]]
// tables, each carrying quoted single-line name/version strings — but a
// parser that "does its best" on the parts it does not fully understand
// (nested tables, multi-line arrays, escaped strings) can attribute a value
// to the wrong package or the wrong field without any error at all. The
// failure mode of guessing at TOML is not a crash, it is a WRONG VERSION,
// and a wrong version that happens to fall outside the vulnerable range is
// a silent false negative — the exact failure class D9 exists to prevent.
// So this reader recognizes only the line shapes poetry.lock is defined to
// produce for the two fields it reads (a bare header line, or `key =
// "single-line value"`) and either ignores or counts anything else — see
// Parse and finalize for exactly which.
//
// Known limit: there is no state for a TOML multi-line string
// (`"""..."""`). A `name` or `version` opened with one would have its
// opening line read as a harmless empty match (parseQuotedAssignment finds
// no closing quote on that line and returns ok=false), and every
// continuation line would then be read as if it were ordinary content of
// whatever block is still open — a continuation line that happened to read
// exactly `name = "..."` would overwrite it, and one starting with `[`
// would end the block early. This is accepted rather than handled: `name`
// and `version` are never multi-line in a poetry-generated lockfile (they
// are identifiers and version strings), and description — the one
// free-text field poetry.lock carries — is always a single-line PyPI
// summary. Handling a case Poetry does not produce would be scope creep
// this task does not need.
package poetrylock

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// pending accumulates the two fields this parser reads from one [[package]]
// table. Both must be present for the block to be usable: a name with no
// version cannot be placed in a comparer's range, and a version with no name
// cannot be turned into a purl or matched against anything.
type pending struct {
	name    string
	version string
}

func (p pending) complete() bool {
	return p.name != "" && p.version != ""
}

// Parse reads the poetry.lock at path and returns the packages it locks.
// path is also what every returned Package's single Location names, and
// what any returned error names — a caller scanning many lockfiles in one
// pass needs to know which one failed.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's own error already names the full path ("open
		// <path>: ..."), so wrapping it again here would only double it up.
		return nil, cyclonedx.Stats{}, err
	}

	var (
		pkgs      []pkgmeta.Package
		stats     cyclonedx.Stats
		cur       pending
		blockOpen bool
		sawHeader bool
	)

	// finalize closes out the block currently being accumulated in cur.
	// Every call increments exactly one of Cataloged/SkippedNoVersion,
	// alongside Components — so nothing this parser saw a [[package]]
	// header for can end up outside the Components == Cataloged + skips
	// invariant every cataloger in this repo holds.
	finalize := func() {
		stats.Components++
		if !cur.complete() {
			// Seen but unusable, and counted rather than dropped: a block
			// silently discarded here is indistinguishable from one that
			// never existed (the argument cyclonedx.go:37-41 makes for
			// nested SBOM components). cyclonedx.Stats has no dedicated
			// "missing name" bucket, so a block missing either field — name,
			// version, or both — is routed through SkippedNoVersion, the
			// same way gomod.go routes both "no path" and "no version"
			// requirements through its own single SkippedNoVersion counter.
			stats.SkippedNoVersion++
			return
		}
		stats.Cataloged++
		pkgs = append(pkgs, pkgmeta.Package{
			Name:      cur.name,
			Version:   cur.version,
			Type:      "pypi",
			Ecosystem: "PyPI",
			// Plain concatenation, the same as gomod.go:96, gobinary.go:60
			// and npmlock: PEP 503 normalization happens once, at match
			// time (pkgmeta.NormalizeName, purl.go:109-128), not here —
			// duplicating that rule in every cataloger is how it drifts out
			// of sync with the one definition the store and matcher both
			// use.
			PURL:      "pkg:pypi/" + cur.name + "@" + cur.version,
			Locations: []pkgmeta.Location{{Path: path}},
		})
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") {
			if line == "[[package]]" {
				// A new package table starts. Whatever was pending from the
				// previous one is now complete, however that turned out —
				// finalize it before resetting cur, or its fields would
				// leak into the block about to start.
				if blockOpen {
					finalize()
				}
				cur = pending{}
				blockOpen = true
				sawHeader = true
			} else {
				// Any other table header — [metadata], [package.source],
				// [[package.dependencies]] — ends the current package
				// block. Its own keys belong to THAT table, not to the
				// package: [package.source] carries a "version" of its own
				// for a git/url dependency, and attributing it to the
				// package would silently overwrite a correct version with
				// an unrelated one.
				if blockOpen {
					finalize()
				}
				blockOpen = false
			}
			continue
		}

		if !blockOpen {
			// Content of some table this parser does not read — [metadata],
			// or the body of a nested table already closed above.
			continue
		}

		key, value, ok := parseQuotedAssignment(line)
		if !ok {
			// An unrecognized line inside a [[package]] block: a non-string
			// value (optional = false), a nested array, anything this
			// parser does not read. Ignored rather than rejected — this
			// parser only ever reads name and version, and everything else
			// in a [[package]] block is exactly this: content it
			// intentionally does not understand.
			continue
		}
		switch key {
		case "name":
			cur.name = value
		case "version":
			cur.version = value
		}
	}
	if serr := scanner.Err(); serr != nil {
		return nil, cyclonedx.Stats{}, fmt.Errorf("read %s: %w", path, serr)
	}
	if blockOpen {
		// EOF with a block open — the last [[package]] in the file, which
		// closes at end-of-file rather than at another header.
		finalize()
	}

	if !sawHeader {
		// Zero [[package]] blocks is not "an empty lockfile" — a real
		// poetry.lock always carries a [metadata] table even with no
		// dependencies. A file with no [[package]] header at all is not a
		// poetry.lock, and returning it as "no packages" would report a
		// clean scan for a file this parser never actually understood.
		return nil, cyclonedx.Stats{}, fmt.Errorf("%s: no [[package]] blocks found", path)
	}

	return pkgs, stats, nil
}

// parseQuotedAssignment recognizes the one line shape this parser reads a
// value from: key = "value", a single-line quoted string with nothing else
// on the line. poetry.lock never spans a name or version across multiple
// lines or uses TOML's other string forms (literal '...', multi-line
// """...""") for either field, so this is the entire grammar this parser
// needs — not a general TOML value parser, and deliberately so: anything
// outside this shape is left to the "unrecognized line" fallback in Parse
// rather than guessed at.
func parseQuotedAssignment(line string) (key, value string, ok bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:eq])
	rest := strings.TrimSpace(line[eq+1:])
	if len(rest) < 2 || rest[0] != '"' {
		return "", "", false
	}
	end := strings.IndexByte(rest[1:], '"')
	if end < 0 {
		return "", "", false
	}
	return key, rest[1 : 1+end], true
}
