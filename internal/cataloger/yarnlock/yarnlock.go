// Package yarnlock turns a yarn.lock file into the normalized package
// inventory the matcher consumes.
//
// Two incompatible formats share the filename "yarn.lock": yarn v1's own
// line-oriented grammar, and yarn berry (v2+), which writes YAML. Parse
// classifies which one a file is (classifyDialect) before reading it, rather
// than trying the v1 parser and hoping it fails loudly on a berry file - it
// does not. Berry writes `version: 1.3.0` where v1 writes `version "1.3.0"`,
// so the v1 parser finds no `version "x"` line anywhere and reports a clean
// zero-package file, which is the exact "found nothing" vs. "did not look"
// confusion this project exists to keep apart.
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
	"gopkg.in/yaml.v3"
)

// ErrUnknownDialect reports that a yarn.lock carries neither yarn v1's
// banner comment nor berry's __metadata block. Both are real markers every
// yarn.lock this parser has been checked against carries; a file with
// neither is a dialect this parser cannot identify, and guessing v1 for it
// (the previous behaviour) risked the same silent zero-package read berry
// itself used to produce.
var ErrUnknownDialect = errors.New("yarn.lock: neither a yarn v1 banner nor a berry __metadata block found")

// Skipped is one berry lockfile entry this parser saw and declined to
// catalog, with why. The v1 path never produces one - see Parse.
type Skipped struct {
	Name   string
	Reason string
}

// Parse reads the yarn.lock at path and returns the packages it resolves,
// alongside every entry a berry file's parse declined to catalog (always nil
// for a v1 file - the v1 grammar's own skips are counted into Stats only, the
// same as before this package read berry at all). path is what every
// returned Package's single Location names and what any returned error
// names, the same as npmlock.Parse - a directory scan reads several
// lockfiles and a bare "yarn.lock" would not say which.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, []Skipped, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's error already carries the full path.
		return nil, cyclonedx.Stats{}, nil, err
	}

	switch classifyDialect(data) {
	case dialectBerry:
		return parseBerry(path, data)
	case dialectV1:
		pkgs, stats, perr := parseV1(path, data)
		return pkgs, stats, nil, perr
	default:
		return nil, cyclonedx.Stats{}, nil, fmt.Errorf("parse %s: %w", path, ErrUnknownDialect)
	}
}

// parseV1 is the original yarn v1 line-oriented parser, unchanged in
// behaviour from before berry was read at all - only its signature moved,
// to make room for Parse's dialect dispatch above.
func parseV1(path string, data []byte) ([]pkgmeta.Package, cyclonedx.Stats, error) {
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

// dialect is which of the two incompatible yarn.lock grammars a file is.
type dialect int

const (
	dialectUnknown dialect = iota
	dialectV1
	dialectBerry
)

// classifyDialect decides which of the two incompatible yarn.lock grammars
// data is.
//
// __metadata is written at the top of every berry lockfile and appears in no
// v1 file; the v1 banner is checked in the same pass and settles the question
// the other way, so whichever marker comes first decides. A file carrying
// neither marker used to be treated as v1 by default - that default is what
// let a berry file that slipped past this classification (or any other
// yarn.lock dialect this parser has never seen) parse as a silent
// zero-package v1 file, so Parse now refuses it instead (ErrUnknownDialect).
func classifyDialect(data []byte) dialect {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "__metadata:"):
			return dialectBerry
		case strings.HasPrefix(line, "# yarn lockfile v1"):
			return dialectV1
		}
	}
	return dialectUnknown
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
// classifyDialect has already routed a berry file to parseBerry instead of
// here by the time this runs.
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

// parseBerry reads a yarn berry (v2+) lockfile. Berry is YAML, and __metadata
// is the only reserved top-level key; every other key is one package entry,
// however the file happened to write it - keys are not always quoted, and a
// multi-descriptor key ("a@npm:^1, a@npm:^2":) still names exactly one
// package. Rather than parse any of that, the name and version come from two
// FIELDS inside the entry (resolution:, version:), which is what makes an
// aliased entry read correctly: an alias only changes the KEY, never the
// resolution.
//
// Decoded with a plain yaml.Node walk of the top-level mapping, the same
// duplicate-key reasoning as pnpmlock: yaml.v3 hard-errors a document with a
// repeated key into a map, and a botched merge-conflict resolution is a real
// way for one to appear in a berry lockfile.
func parseBerry(path string, data []byte) ([]pkgmeta.Package, cyclonedx.Stats, []Skipped, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, cyclonedx.Stats{}, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		// A __metadata: line was seen (classifyDialect would not have routed
		// here otherwise), but the document as a whole is not a mapping -
		// nothing this parser can read a package entry out of.
		return nil, cyclonedx.Stats{}, nil, fmt.Errorf("parse %s: not a mapping at the top level", path)
	}
	root := doc.Content[0]

	var (
		pkgs    []pkgmeta.Package
		stats   cyclonedx.Stats
		skipped []Skipped
		seen    = map[string]bool{}
	)

	for i := 0; i+1 < len(root.Content); i += 2 {
		key, entry := root.Content[i], root.Content[i+1]
		if key.Value == "__metadata" {
			continue
		}
		if entry.Kind != yaml.MappingNode {
			stats.Components++
			stats.SkippedNoPURL++
			skipped = append(skipped, Skipped{Name: key.Value, Reason: "entry is not a mapping"})
			continue
		}

		resNode := findMapValue(entry, "resolution")
		if resNode == nil || resNode.Value == "" {
			stats.Components++
			stats.SkippedNoPURL++
			skipped = append(skipped, Skipped{Name: key.Value, Reason: "no resolution: field"})
			continue
		}

		name, proto, _, ok := splitResolution(resNode.Value)
		if !ok {
			stats.Components++
			stats.SkippedNoPURL++
			skipped = append(skipped, Skipped{
				Name:   key.Value,
				Reason: "resolution has no recognizable protocol boundary: " + resNode.Value,
			})
			continue
		}

		switch {
		case proto == "npm":
			version := findScalar(entry, "version")
			if version == "" {
				// Not observed across 8,700+ real entries checked against
				// this reader (version: always agreed with resolution's own
				// version where both were present), so this is a defensive
				// arm rather than a shape the corpus has actually shown.
				stats.Components++
				stats.SkippedNoVersion++
				skipped = append(skipped, Skipped{Name: name, Reason: "resolves through npm but has no version: field"})
				continue
			}
			dedupeKey := name + "@" + version
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true
			stats.Components++
			stats.Cataloged++
			pkgs = append(pkgs, pkgmeta.Package{
				Name:      name,
				Version:   version,
				Type:      "npm",
				Ecosystem: "npm",
				PURL:      "pkg:npm/" + name + "@" + version,
				Locations: []pkgmeta.Location{{Path: path}},
			})

		case isLocalProtocol(proto):
			// A workspace member, or a link:/portal:/file:/exec: dependency
			// resolved to something local to this checkout. Nothing
			// published behind it to place in an advisory range - shown so
			// it is not silently absent, but deliberately not counted into
			// Stats (see pnpmlock's identical causeLocal for why: this is
			// not incompleteness the target gate should trip on).
			skipped = append(skipped, Skipped{
				Name:   name,
				Reason: "a local " + proto + ": dependency, nothing to evaluate",
			})

		case proto == "https":
			// Yarn normalizes a git dependency into an https: resolution
			// (e.g. a GitHub shorthand becomes a full clone URL). Its own
			// version: field is the FORK's self-declared version, not a
			// registry release - reporting it risks both a false positive
			// (this exact string never had that CVE fixed) and a false
			// negative (the real fix landed under a different version
			// entirely), so it is skipped as a reachable gap rather than
			// trusted.
			stats.Components++
			stats.SkippedNoVersion++
			skipped = append(skipped, Skipped{
				Name:   name,
				Reason: "resolution normalizes to a git URL, not a registry version",
			})

		case proto == "patch":
			// Silent, deliberately, unlike every other skip above: the
			// package a patch: entry patches is ALWAYS also present as its
			// own separate npm: entry (verified 17/17 across two real
			// lockfiles - an empirical invariant observed in the corpus,
			// not a guarantee the berry format documents). Reporting this as
			// a skip would just be noise duplicating what that npm: twin
			// already reports for the same name and version.
			continue

		default:
			stats.Components++
			stats.SkippedNoPURL++
			skipped = append(skipped, Skipped{
				Name:   name,
				Reason: "resolution uses an unrecognized protocol " + proto + ":",
			})
		}
	}

	return pkgs, stats, skipped, nil
}

// isLocalProtocol reports whether proto resolves to something local to this
// checkout rather than a package assay could look up anywhere else.
func isLocalProtocol(proto string) bool {
	switch proto {
	case "workspace", "link", "portal", "file", "exec":
		return true
	}
	return false
}

// splitResolution splits a berry resolution string into the real package
// name, its protocol, and everything after the protocol's colon.
//
// Splitting at the LAST "@" is wrong: a patch: resolution embeds a second
// locator of its own ("typescript@patch:typescript@npm%3A5.9.2#..."), so the
// last "@" lands inside that nested locator rather than at the real
// boundary. The correct rule is the FIRST "@" that is followed by one or
// more lowercase letters and then a literal ":" - scanning from index 1
// (rather than 0) is what lets a scoped name's own leading "@" survive,
// requiring a literal ":" is what keeps a URL-encoded "npm%3A" from
// matching, and requiring the letters to be lowercase is what a real
// protocol name always is even when the package name itself is not
// (JSONStream@npm:1.3.5, a real package).
func splitResolution(res string) (name, proto, rest string, ok bool) {
	for i := 1; i < len(res); i++ { // start at 1: index 0 may be a scope '@'
		if res[i] != '@' {
			continue
		}
		j := i + 1
		for j < len(res) && res[j] >= 'a' && res[j] <= 'z' {
			j++
		}
		if j > i+1 && j < len(res) && res[j] == ':' {
			return res[:i], res[i+1 : j], res[j+1:], true
		}
	}
	return "", "", "", false
}

// findMapValue returns the value node paired with key in a MappingNode's
// Content, or nil if n is not a mapping or carries no such key. See
// pnpmlock.findMapValue for the duplicate-key reasoning this mirrors.
func findMapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// findScalar is findMapValue plus unwrapping the raw scalar text, or "" if
// the key is absent.
func findScalar(n *yaml.Node, key string) string {
	v := findMapValue(n, key)
	if v == nil {
		return ""
	}
	return v.Value
}
