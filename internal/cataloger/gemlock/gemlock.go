// Package gemlock turns a Gemfile.lock file into the normalized package
// inventory the matcher consumes.
//
// Gemfile.lock is bundler's own text format - not TOML, JSON or YAML - so
// this reads it as lines rather than reusing tomlblock or a generic decoder.
// The shape that matters is narrow: the GEM section's "specs:" block lists
// one resolved gem per line at exactly 4 spaces of indent, "name (version)",
// followed by that gem's own dependency constraints at 6 spaces. Those
// 6-space lines are not packages - they are what the 4-space entry above
// them depends on, still expressed as a version constraint rather than a
// resolved version - and are skipped rather than parsed.
package gemlock

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// Parse reads the Gemfile.lock at path and returns the packages it resolves.
// path is what every returned Package's single Location names and what any
// returned error names, the same as the other per-file catalogers.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's error already carries the full path.
		return nil, cyclonedx.Stats{}, err
	}

	var (
		pkgs    []pkgmeta.Package
		stats   cyclonedx.Stats
		section string // the current unindented header: "GEM", "GIT", "PATH", ...
		inSpecs bool   // whether "  specs:" has been seen since the last header
	)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		indent := leadingSpaces(line)
		if indent == 0 {
			// An unindented line ends whatever section came before it and
			// starts a new one. PLATFORMS, DEPENDENCIES and BUNDLED WITH all
			// arrive this way and carry no specs: block of their own, so
			// inSpecs simply never turns true again while one of them is
			// current.
			section = strings.TrimSpace(line)
			inSpecs = false
			continue
		}

		if indent == 2 && strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}

		if indent != 4 || !inSpecs {
			// Everything else at this depth - "remote:"/"revision:" at 2
			// spaces, a spec's own dependency constraints at 6 - names no
			// package of its own. The 6-space case is the one that matters:
			// it is a version CONSTRAINT ("= 7.0.4", "~> 2.0"), not a
			// resolved version, and treating it as a package would count the
			// same gem twice under two different "versions".
			continue
		}

		name, version, ok := specLine(line)
		if !ok {
			// Indented correctly but not "name (version)" - malformed rather
			// than absent. Counted, not dropped: a spec line that vanishes
			// here is indistinguishable from one that was never in the file,
			// which breaks the Components == Cataloged + skips invariant.
			stats.Components++
			stats.SkippedNoVersion++
			continue
		}

		stats.Components++

		if section != "GEM" {
			// GIT and PATH specs resolve a real gem too, but not from
			// rubygems.org - the source is a fork or a local checkout, and a
			// fork's version number carries no promise that it matches the
			// upstream advisory data this scan compares against. Same
			// treatment as Pipfile's VCS entries (D26's argument, applied
			// here).
			stats.SkippedNoVersion++
			continue
		}

		stats.Cataloged++
		pkgs = append(pkgs, pkgmeta.Package{
			Name:    name,
			Version: version,
			Type:    "gem",
			// Plain concatenation, as pipfilelock and poetrylock do:
			// normalization happens once, at match time
			// (pkgmeta.NormalizeName), not duplicated here.
			Ecosystem: "RubyGems",
			PURL:      "pkg:gem/" + name + "@" + version,
			Locations: []pkgmeta.Location{{Path: path}},
		})
	}

	return pkgs, stats, nil
}

// leadingSpaces counts the space characters at the start of line. Gemfile.lock
// is bundler's own output and is always space-indented, never tabs.
func leadingSpaces(line string) int {
	n := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		n++
	}
	return n
}

// specLine parses a "specs:" entry already known to sit at exactly 4 spaces
// of indent: "name (version)", optionally with a platform suffix bundler
// appends for a native gem ("nokogiri (1.13.8-x86_64-linux)"). That suffix is
// kept as part of the version rather than stripped - the Comparer, not this
// cataloger, owns what counts as an equivalent version (D9).
func specLine(line string) (name, version string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasSuffix(trimmed, ")") {
		return "", "", false
	}
	open := strings.LastIndex(trimmed, " (")
	if open < 0 {
		return "", "", false
	}
	name = trimmed[:open]
	version = trimmed[open+2 : len(trimmed)-1]
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}
