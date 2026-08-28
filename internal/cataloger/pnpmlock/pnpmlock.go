// Package pnpmlock turns a pnpm-lock.yaml file into the normalized package
// inventory, reading only the packages: section (D103).
//
// pnpm has written three key grammars under one lockfileVersion field across
// its history (5.x, 6.x, 9.x — see shapeFor), and a lockfile can hold more
// than one YAML document: pnpm's own pinned-binaries block is sometimes
// written ahead of the project document, under the same file, separated by
// "---". yaml.Unmarshal reads the first document only and would silently
// lose every real dependency in that shape, so this reader streams with
// yaml.NewDecoder instead and unions every document's packages: section.
//
// Every other top-level section (importers, snapshots, dependencies) is
// deliberately unread. importers never names a package that packages: does
// not also carry, and snapshots is packages: again with its peer-dependency
// suffix stripped — reading packages: alone is proven complete against both,
// and it is also what disposes of aliases, workspace links and pnpm's
// catalogs feature in one decision: none of those change what packages:
// says was actually resolved.
//
// Decoding walks yaml.Node mappings by hand rather than into a
// map[string]T. yaml.v3 hard-errors decoding a document with a duplicate key
// into a map, and real lockfiles carry them (a botched merge-conflict
// resolution is the observed cause) — a map decode would lose the entire
// file over one repeated key. Node walking bypasses that check; dedupe on
// name@version happens explicitly below instead.
package pnpmlock

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
	"gopkg.in/yaml.v3"
)

// Skipped is one packages: entry this parser saw and declined to catalog,
// with why. Named and returned rather than folded into a bare count, the
// same reasoning as requirements.Unusable: a reader told only "3 skipped"
// cannot act on it, but told which three (and why) can go fix the file or
// decide the gap does not matter.
type Skipped struct {
	Name   string
	Reason string
}

// pnpmShape is which packages: key grammar applies, chosen from
// lockfileVersion by range rather than by exact match — see shapeFor.
type pnpmShape int

const (
	shapeV5 pnpmShape = iota
	// shapeV6Plus covers both 6.x and 9.x: their key grammars are the same
	// function (strip a peer-dependency suffix, drop a leading "/" that v9
	// never has anyway, split on the last "@"). They are kept as separate
	// named ranges in shapeFor rather than collapsed into one boundary check,
	// so a future version whose grammar actually diverges from 6.x has
	// somewhere to branch without re-deriving the range logic.
	shapeV6Plus
)

// shapeFor maps a lockfileVersion string to the key grammar that applies.
//
// Decided by range, never equality: "5.4", "6.0" and "9.0" are the versions
// this parser has been checked against, but pnpm has shipped in-between
// values before ("5.3", "5.4") and a strict equality list would treat every
// one of those as unparseable. ParseFloat is safe here specifically because
// yaml.v3 preserves a scalar's literal text in Node.Value regardless of
// whether the file wrote it quoted ('6.0', a string) or bare (5.4, a
// number) — the caller reads that raw text, not a coerced Go value, so
// "6.0" parses to 6.0 either way.
func shapeFor(lockfileVersion string) (pnpmShape, error) {
	f, err := strconv.ParseFloat(lockfileVersion, 64)
	if err != nil {
		return 0, fmt.Errorf("lockfileVersion %q is not a version number this parser understands", lockfileVersion)
	}
	if f < 6.0 {
		return shapeV5, nil
	}
	return shapeV6Plus, nil
}

// Parse reads the pnpm-lock.yaml at path and returns the packages it
// resolves, alongside every packages: entry it declined and why. path is
// what every returned Package's single Location names and what any error
// names, matching every other cataloger in this repo.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, []Skipped, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, cyclonedx.Stats{}, nil, err
	}
	defer f.Close()

	var (
		pkgs        []pkgmeta.Package
		stats       cyclonedx.Stats
		skipped     []Skipped
		seen        = map[string]bool{}
		lockVersion string
		haveVersion bool
	)

	dec := yaml.NewDecoder(f)
	for docIndex := 0; ; docIndex++ {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			if docIndex == 0 {
				// The first document is the only one that can invalidate the
				// whole file: nothing has been kept yet, so there is nothing
				// to lose by refusing outright.
				return nil, cyclonedx.Stats{}, nil, fmt.Errorf("parse %s: %w", path, err)
			}
			// A later document failed. Everything read from the documents
			// before it is real and is kept — discarding it over a problem
			// in a document that, per pnpm's own multi-document use, is
			// often just the pinned-binaries block anyway would cost real
			// packages for no reason. What is lost genuinely is a gap the
			// target gate should see, the same as a malformed entry.
			stats.Components++
			stats.SkippedNoPURL++
			skipped = append(skipped, Skipped{
				Name:   fmt.Sprintf("(document %d)", docIndex),
				Reason: fmt.Sprintf("could not decode: %v", err),
			})
			break
		}

		// A document that is empty or holds only a comment decodes to a
		// DocumentNode with no content, or one whose single child is the
		// YAML null tag. Neither carries a packages: section to read.
		if len(doc.Content) == 0 || doc.Content[0].Tag == "!!null" {
			continue
		}
		root := doc.Content[0]

		if v := findMapValue(root, "lockfileVersion"); v != nil && v.Value != "" {
			// A document with no lockfileVersion of its own inherits
			// whichever one an earlier document already established -
			// pnpm's pinned-binaries document does not carry one.
			lockVersion = v.Value
			haveVersion = true
		}

		pkgsNode := findMapValue(root, "packages")
		if pkgsNode == nil || pkgsNode.Kind != yaml.MappingNode {
			continue
		}
		if !haveVersion {
			return nil, cyclonedx.Stats{}, nil,
				fmt.Errorf("parse %s: packages: section with no lockfileVersion established yet", path)
		}
		shape, serr := shapeFor(lockVersion)
		if serr != nil {
			return nil, cyclonedx.Stats{}, nil, fmt.Errorf("parse %s: %w", path, serr)
		}

		for i := 0; i+1 < len(pkgsNode.Content); i += 2 {
			key := pkgsNode.Content[i].Value
			entry := pkgsNode.Content[i+1]

			var (
				name, version string
				ok            bool
			)
			if shape == shapeV5 {
				name, version, ok = parseKeyV5(key)
			} else {
				name, version, ok = parseKeyV6Plus(key)
			}
			if !ok {
				// 0 observed in the corpus this parser was checked against;
				// any hit is a key grammar this parser has not learned yet,
				// which is exactly what a reader needs to know rather than a
				// silently dropped entry.
				stats.Components++
				stats.SkippedNoPURL++
				skipped = append(skipped, Skipped{
					Name:   key,
					Reason: fmt.Sprintf("packages: key does not match the lockfileVersion %s grammar", lockVersion),
				})
				continue
			}

			switch classifyResolution(readResolution(entry)) {
			case causeRegistry:
				dedupeKey := name + "@" + version
				if seen[dedupeKey] {
					// The same package can legitimately appear more than
					// once across a multi-document file's packages:
					// sections. Silent: this is not a gap, it is the same
					// fact stated twice.
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
			case causeLocal:
				// A workspace member reached through link:/file:/a directory
				// resolution. There is no published version behind it to
				// place inside an advisory range - not a gap in what this
				// scan could reach, just nothing to reach. Shown so it is
				// not silently absent, but deliberately not counted into
				// Stats: doing so would make cyclonedx.Stats.Components
				// (and, through it, the target-incompleteness gate) count a
				// workspace member the same as a real unresolved dependency.
				skipped = append(skipped, Skipped{
					Name:   name + "@" + version,
					Reason: "a local workspace/link/directory dependency, nothing to evaluate",
				})
			case causeGit:
				// A real dependency this scan cannot place in an advisory
				// range - a git commit or non-registry tarball rather than a
				// released version. Unlike the local case above, this is a
				// package the matcher genuinely could not reach.
				stats.Components++
				stats.SkippedNoVersion++
				skipped = append(skipped, Skipped{
					Name:   name + "@" + version,
					Reason: "resolves to a non-registry source (git or foreign tarball), not a version a comparer can place in a range",
				})
			default: // causeMalformed
				stats.Components++
				stats.SkippedNoPURL++
				skipped = append(skipped, Skipped{
					Name:   name + "@" + version,
					Reason: "resolution carries none of the fields (integrity, type, tarball, directory, repo) this parser recognizes",
				})
			}
		}
	}

	if !haveVersion {
		return nil, cyclonedx.Stats{}, nil, fmt.Errorf("parse %s: no lockfileVersion found", path)
	}

	return pkgs, stats, skipped, nil
}

// parseKeyV5 parses a lockfileVersion < 6.0 packages: key, e.g.
// "/@babel/core/7.17.10" or "/webpack-cli/4.10.0_fzn43tb6bdtdxy2s3aqevve2su".
//
// Order is load-bearing. The "(" split for a peer-dependency suffix must run
// FIRST: a peer suffix embeds both "@" and "/" characters of its own
// ("_@babel+core@7.17.10"), so splitting on the real separator before
// stripping it would cut the wrong string in two. The separator split then
// takes the LAST "/", because a scoped name ("@babel/core") already
// contains one - splitting on the first would cut the scope from its own
// name. Only after that does the "_" cut apply, and only to the version
// half: "_" is not legal in semver, so cutting there safely handles both a
// named peer suffix and pnpm's hashed one.
func parseKeyV5(key string) (name, version string, ok bool) {
	k := strings.SplitN(key, "(", 2)[0]
	k = strings.TrimPrefix(k, "/")

	i := strings.LastIndex(k, "/")
	if i <= 0 {
		return "", "", false
	}
	name, verPart := k[:i], k[i+1:]
	if verPart == "" {
		return "", "", false
	}
	if u := strings.IndexByte(verPart, '_'); u >= 0 {
		verPart = verPart[:u]
	}
	if verPart == "" {
		return "", "", false
	}
	return name, verPart, true
}

// parseKeyV6Plus parses a lockfileVersion 6.x or 9.x packages: key, e.g.
// "/@babel/parser@7.18.4(@babel/types@7.19.0)" (6.x) or
// "@ampproject/remapping@2.3.0" (9.x, no leading "/" at all - TrimPrefix is
// a no-op for it rather than a version-specific branch). Both grammars
// split on the LAST "@" once the peer suffix is gone, for the same scoped-name
// reason parseKeyV5 splits on the last "/".
func parseKeyV6Plus(key string) (name, version string, ok bool) {
	k := strings.SplitN(key, "(", 2)[0]
	k = strings.TrimPrefix(k, "/")

	i := strings.LastIndex(k, "@")
	if i <= 0 {
		return "", "", false
	}
	name, version = k[:i], k[i+1:]
	if version == "" {
		return "", "", false
	}
	return name, version, true
}

// cause is which of the three dispositions a packages: entry's resolution
// object earns. Exactly three, matching D103's classification: causeLocal is
// counted and shown but must never reach Stats (it is not an incompleteness
// the target gate should trip on); causeGit and causeMalformed are both fed
// into Stats because both are real coverage the scan could not reach.
type cause int

const (
	causeMalformed cause = iota
	causeRegistry
	causeLocal
	causeGit
)

// resolution is the fields of a packages: entry's resolution: object that
// decide which cause it earns. Read, never inferred from the key or the
// version string: a git commit hash beginning with a digit passes any
// version-shape heuristic and would otherwise be emitted as a real package
// version.
type resolution struct {
	integrity, typ, tarball, directory, repo, commit string
}

// readResolution extracts the resolution: object nested under a packages:
// entry. A missing or non-mapping resolution: field returns the zero value,
// which classifyResolution routes to causeMalformed - there is nothing here
// to classify a real disposition from.
func readResolution(entry *yaml.Node) resolution {
	res := findMapValue(entry, "resolution")
	if res == nil || res.Kind != yaml.MappingNode {
		return resolution{}
	}
	return resolution{
		integrity: scalarValue(findMapValue(res, "integrity")),
		typ:       scalarValue(findMapValue(res, "type")),
		tarball:   scalarValue(findMapValue(res, "tarball")),
		directory: scalarValue(findMapValue(res, "directory")),
		repo:      scalarValue(findMapValue(res, "repo")),
		commit:    scalarValue(findMapValue(res, "commit")),
	}
}

// classifyResolution decides a packages: entry's disposition from its
// resolution object, per pnpm's own resolution shapes: a plain registry
// package carries integrity and nothing else; a workspace member is
// type: directory; a git dependency is type: git or carries repo+commit (or,
// for pnpm 5.x's git keys, a tarball URL whose host is not npm's registry);
// and type: binary or a custom:* resolver is a non-registry source assay
// treats the same way as git for evaluation purposes - a real dependency it
// cannot place in an advisory range.
func classifyResolution(r resolution) cause {
	switch {
	case r.typ == "directory":
		return causeLocal
	case r.typ == "git", r.repo != "" && r.commit != "":
		return causeGit
	case r.tarball != "":
		if isNpmRegistryTarball(r.tarball) {
			return causeRegistry
		}
		return causeGit
	case r.typ == "binary", strings.HasPrefix(r.typ, "custom:"):
		return causeGit
	case r.integrity != "":
		return causeRegistry
	default:
		return causeMalformed
	}
}

// isNpmRegistryTarball reports whether a resolution's tarball URL is hosted
// on npm's own registry. pnpm sometimes writes an explicit tarball URL
// alongside integrity for an ordinary registry package rather than omitting
// it, so a bare "has a tarball field" check would misclassify those as
// non-registry; the host is what actually distinguishes a registry mirror
// from a git-derived or third-party tarball.
func isNpmRegistryTarball(tarball string) bool {
	u, err := url.Parse(tarball)
	if err != nil {
		return false
	}
	return u.Host == "registry.npmjs.org"
}

// findMapValue returns the value node paired with key in a MappingNode's
// Content, or nil if n is not a mapping or carries no such key. Walking
// Content in pairs rather than decoding into a map is what lets this parser
// read a document containing a duplicate key at all (see the package doc).
// A duplicate is resolved to its FIRST occurrence, which only matters for
// the handful of once-per-document keys (lockfileVersion, packages,
// resolution, ...) this is used for - duplicate PACKAGE entries within
// packages: are walked directly in Parse's own loop, not through this
// function, so both of a duplicate's occurrences are seen there.
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

// scalarValue returns n's raw scalar text, or "" if n is nil. A field this
// parser looks for but the file did not write (n == nil) and a field the
// file wrote as an explicit empty string are indistinguishable here, which
// is fine: every caller treats "" as "absent" either way.
func scalarValue(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	return n.Value
}
