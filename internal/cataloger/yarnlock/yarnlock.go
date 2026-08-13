// Package yarnlock turns a yarn.lock file into the normalized package
// inventory the matcher consumes.
//
// Only yarn v1 is read. Yarn berry (v2+) writes YAML under the same filename,
// and reading it is deferred rather than attempted: see ErrBerry below for why
// a refusal is the only safe answer when two incompatible formats share a name.
package yarnlock

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// ErrBerry reports that the file is a yarn berry lockfile, which this parser
// does not read.
//
// It is a distinct error rather than a generic parse failure because the two
// formats share the filename "yarn.lock", and the v1 parser does not FAIL on a
// berry file - it succeeds and finds nothing. Berry writes `version: 1.3.0`
// where v1 writes `version "1.3.0"`, so every entry silently yields no version
// and the file reports zero packages. That is a clean verdict over a lockfile
// nobody read, which is the exact failure mode this repo refuses everywhere
// else. Detecting the format and refusing is the only honest option until a
// YAML parser is a dependency this project is willing to take.
var ErrBerry = errors.New("yarn berry (v2+) lockfile: assay reads yarn v1 only")

// Parse reads the yarn.lock at path and returns the packages it resolves.
// path is what every returned Package's single Location names and what any
// returned error names, the same as npmlock.Parse - a directory scan reads
// several lockfiles and a bare "yarn.lock" would not say which.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's error already carries the full path.
		return nil, cyclonedx.Stats{}, err
	}

	if isBerry(data) {
		return nil, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", path, ErrBerry)
	}

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
		// open tracks whether a header has been seen, separately from whether
		// that header yielded a name. The two are not the same: a header this
		// parser cannot turn into a name is still an entry the file declared,
		// and folding them into one variable makes it vanish from every
		// counter rather than be counted as a skip.
		open    bool
		name    string
		version string
	)

	// finalize closes the entry in name/version. Every call increments exactly
	// one of Cataloged/SkippedNoVersion alongside Components, so nothing this
	// parser saw a header for escapes the Components == Cataloged + skips
	// invariant every cataloger in this repo holds.
	finalize := func() {
		if !open {
			return
		}
		stats.Components++
		if name == "" || version == "" {
			// A header with no `version` line, or one this parser could not
			// turn into a name. Malformed, or an entry whose resolution
			// failed - either way there is nothing for a comparer to place
			// inside an advisory range, so it is counted and named rather
			// than dropped. cyclonedx.Stats has no separate "missing name"
			// bucket, so both route through SkippedNoVersion, as
			// poetrylock.go does for the same reason.
			stats.SkippedNoVersion++
			open, name, version = false, "", ""
			return
		}
		stats.Cataloged++
		pkgs = append(pkgs, pkgmeta.Package{
			Name:    name,
			Version: version,
			Type:    "npm",
			// Plain concatenation, as in npmlock and poetrylock: name
			// normalization belongs at match time (pkgmeta.NormalizeName),
			// not duplicated into every cataloger where it drifts.
			Ecosystem: "npm",
			PURL:      "pkg:npm/" + name + "@" + version,
			Locations: []pkgmeta.Location{{Path: path}},
		})
		open, name, version = false, "", ""
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// An entry header sits at column zero and ends in a colon. Indentation
		// is what separates a header from the fields belonging to it, so the
		// test is on the raw line rather than the trimmed one.
		if line[0] != ' ' && line[0] != '\t' && strings.HasSuffix(trimmed, ":") {
			finalize()
			open = true
			name = nameFromSpecs(strings.TrimSuffix(trimmed, ":"))
			continue
		}

		if open && version == "" {
			if v, ok := versionField(trimmed); ok {
				version = v
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, cyclonedx.Stats{}, fmt.Errorf("read %s: %w", path, err)
	}
	finalize()

	return pkgs, stats, nil
}

// isBerry reports whether data is a yarn berry lockfile rather than a v1 one.
//
// __metadata is written at the top of every berry lockfile and appears in no
// v1 file. The v1 banner is checked in the same pass and settles the question
// the other way, so whichever marker comes first decides - a file carrying
// neither is treated as v1, which is the status quo for the hand-written
// fixtures and older files that omit the banner.
func isBerry(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "__metadata:"):
			return true
		case strings.HasPrefix(line, "# yarn lockfile v1"):
			// The explicit v1 banner settles it. Berry never writes this line.
			return false
		}
	}
	return false
}

// nameFromSpecs turns an entry header into the package name it describes.
//
// A header names one package through one or more comma-separated specs, each
// "<name>@<range>", any of which may be quoted:
//
//	lodash@^4.17.0, lodash@~4.17.15:
//	"@babel/core@^7.0.0":
//
// Every spec on a header resolves to the same package, so the first is enough.
func nameFromSpecs(header string) string {
	spec := header
	if i := strings.Index(spec, ","); i >= 0 {
		spec = spec[:i]
	}
	spec = strings.TrimSpace(spec)
	spec = strings.Trim(spec, `"`)

	// An aliased dependency is installed under a name the project chose:
	//
	//	"aliased@npm:lodash@^4.0.0":
	//
	// What is on disk, and what an advisory is written against, is lodash -
	// the alias is local to this project and matches nothing. Splitting on the
	// last @ alone would yield "aliased@npm:lodash", a name no ecosystem has,
	// and a package that matches no advisory is a false NEGATIVE: silent, and
	// the failure this repo ranks worst.
	if i := strings.LastIndex(spec, "@npm:"); i > 0 {
		spec = spec[i+len("@npm:"):]
	}

	// Split on the LAST @, not the first. A scoped package's name begins with
	// one ("@babel/core@^7.0.0"), so splitting on the first yields an empty
	// name and a range that swallows the rest - the single most likely way to
	// get this wrong, and silent, since an empty name matches no advisory.
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		// at == 0 is a spec that is nothing but a scope marker, at == -1 a
		// spec with no range at all. Neither names a package this parser can
		// stand behind, so it returns empty and finalize counts the entry as
		// a skip rather than inventing a name.
		return ""
	}
	return spec[:at]
}

// versionField extracts the resolved version from a v1 `version "1.2.3"` line.
// Berry's unquoted `version: 1.2.3` is deliberately NOT accepted: a file
// mixing the two is not something this parser can claim to understand, and
// isBerry has already refused the whole file by the time this runs.
func versionField(trimmed string) (string, bool) {
	const key = "version "
	if !strings.HasPrefix(trimmed, key) {
		return "", false
	}
	v := strings.TrimSpace(trimmed[len(key):])
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", false
	}
	v = v[1 : len(v)-1]
	if v == "" {
		return "", false
	}
	return v, true
}
