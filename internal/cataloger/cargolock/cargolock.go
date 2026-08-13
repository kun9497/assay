// Package cargolock turns a Cargo.lock file into the normalized package
// inventory the matcher consumes.
//
// Cargo.lock is TOML, and this reads it with a line scanner rather than a TOML
// parser, the same way poetrylock does for poetry.lock. That is a deliberate
// limit rather than an oversight: the file is a flat sequence of [[package]]
// blocks whose two interesting fields are bare quoted strings, so the subset
// needed here is small and stable. It is also why pnpm-lock.yaml is refused
// instead (D61) — YAML's is neither.
package cargolock

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// Parse reads the Cargo.lock at path and returns the packages it resolves.
// path is what every returned Package's single Location names and what any
// returned error names.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's error already carries the full path.
		return nil, cyclonedx.Stats{}, err
	}

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
		// open is whether a [[package]] header has been seen, tracked apart
		// from whether it yielded a name: a block this parser cannot name is
		// still a block the file declared, and keying "is a block open" off
		// the name makes it vanish from every counter instead of being
		// counted as a skip.
		open    bool
		name    string
		version string
	)

	finalize := func() {
		if !open {
			return
		}
		stats.Components++
		if name == "" || version == "" {
			// Counted, then skipped. cyclonedx.Stats has no separate
			// "missing name" bucket, so both route through SkippedNoVersion
			// as poetrylock does for the same reason.
			stats.SkippedNoVersion++
			open, name, version = false, "", ""
			return
		}
		stats.Cataloged++
		pkgs = append(pkgs, pkgmeta.Package{
			Name:    name,
			Version: version,
			Type:    "cargo",
			// The purl type and the ecosystem key are different strings:
			// pkg:cargo/<crate>, but OSV keys the ecosystem "crates.io".
			// Writing "cargo" here would send every lookup to a bucket that
			// does not exist, and a lookup that finds nothing reports clean.
			Ecosystem: "crates.io",
			PURL:      "pkg:cargo/" + name + "@" + version,
			Locations: []pkgmeta.Location{{Path: path}},
		})
		open, name, version = false, "", ""
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[[package]]" {
			finalize()
			open = true
			continue
		}
		// Any other table header ends the block. Cargo.lock v1 wrote a
		// trailing [metadata] table holding checksums, and its keys are quoted
		// strings containing the word "name" - reading on past it would let
		// that table's contents overwrite the last package's fields.
		if strings.HasPrefix(line, "[") {
			finalize()
			continue
		}
		if !open {
			continue
		}

		// Only the FIRST assignment of each field is taken. A block's own
		// name and version appear once, at the top; "name" also appears
		// inside the inline tables of a [[package.dependencies]]-style entry
		// in some generators, and letting a later one win would rename the
		// package to one of its dependencies.
		if name == "" {
			if v, ok := stringField(line, "name"); ok {
				name = v
				continue
			}
		}
		if version == "" {
			if v, ok := stringField(line, "version"); ok {
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

// stringField matches `key = "value"` and returns the value.
//
// The key is compared exactly rather than by prefix: "version" is a prefix of
// nothing here, but "name" is a prefix of nothing only by luck, and a prefix
// test would make a future "name_hint" field silently become the name.
func stringField(line, key string) (string, bool) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", false
	}
	if strings.TrimSpace(line[:eq]) != key {
		return "", false
	}
	v := strings.TrimSpace(line[eq+1:])
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		// Not a quoted scalar: an inline table, an array, or a multi-line
		// value this parser does not read. Neither field it wants is ever
		// written that way.
		return "", false
	}
	v = v[1 : len(v)-1]
	if v == "" {
		return "", false
	}
	return v, true
}
