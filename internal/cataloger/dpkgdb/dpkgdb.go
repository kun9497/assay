// Package dpkgdb turns Debian's installed-package database into the normalized
// inventory.
//
// The file is deb822, not RFC822, and the difference is not academic — dpkg's
// own parse_stanza() accepts three things a textproto-style reader rejects or
// mangles:
//
//   - whitespace before the colon ("Package : bash" parses);
//   - field names matched case-INSENSITIVELY, which is the exact opposite of
//     the apk database's case-significant "P:" versus "p:" and the habit not to
//     carry across from the cataloger next door;
//   - continuation on ANY whitespace, space or tab. syft tests only for a
//     leading space, so a tab-continued field becomes a new field, fails to
//     find a colon, and is silently dropped.
//
// Two upstream bugs are avoided here deliberately, both in reading the Status
// field, and both of which drop a package that is installed:
//
//   - syft substring-matches "deinstall", so "deinstall ok installed" — a
//     package marked for removal whose files are still on disk — vanishes;
//   - trivy scans for any word equal to "deinstall" or "purge", so
//     "purge ok installed" vanishes too.
//
// Only the THIRD word says whether files are present. The first is a future
// intent and the second an error marker.
package dpkgdb

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// installedPath is where the database lives on an ordinary Debian or Ubuntu
// image. Distroless images use a directory instead; see ParseDir.
const installedPath = "/var/lib/dpkg/status"

// installedStates are the Status values whose third word means the package's
// files are on disk, and therefore that its vulnerabilities are reachable.
//
// half-installed is included on purpose. Its files may be present, and this is
// the one place the two errors are not symmetric: over-reporting is a finding
// somebody investigates, under-reporting is a vulnerability nobody sees.
var installedStates = map[string]bool{
	"installed":        true,
	"unpacked":         true,
	"half-configured":  true,
	"half-installed":   true,
	"triggers-awaited": true,
	"triggers-pending": true,
	// Excluded: config-files (files removed, configuration kept) and
	// not-installed. Neither has the package's own files on disk.
}

// Parse reads one dpkg status file and returns the packages it lists.
//
// ecosystem is passed in rather than derived, for apkdb's reason: this function
// never sees /etc/os-release, and a cataloger that guessed its own ecosystem
// key would be inventing the release the whole lookup depends on (D6).
func Parse(r io.Reader, ecosystem string) ([]pkgmeta.Package, error) {
	return parseStanzas(r, ecosystem, installedPath)
}

// ParseStanza reads a single-package file, the shape distroless images use:
// /var/lib/dpkg/status.d/ is a DIRECTORY of one stanza per package rather than
// one file holding all of them. path is recorded on the Location so a report
// names the file the package actually came from.
func ParseStanza(r io.Reader, ecosystem, path string) ([]pkgmeta.Package, error) {
	return parseStanzas(r, ecosystem, path)
}

func parseStanzas(r io.Reader, ecosystem, path string) ([]pkgmeta.Package, error) {
	var (
		out    []pkgmeta.Package
		fields = map[string]string{}
		last   string
	)
	flush := func() error {
		if len(fields) == 0 {
			return nil
		}
		p, ok, err := toPackage(fields, ecosystem, path)
		fields = map[string]string{}
		last = ""
		if err != nil {
			return err
		}
		if ok {
			out = append(out, p)
		}
		return nil
	}

	sc := bufio.NewScanner(r)
	// A Description field can be long, and the default 64 KiB token is ample
	// for it. A file that exceeds it should fail loudly rather than be read in
	// part, which sc.Err() below ensures.
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")
		if line == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		// Continuation: ANY leading whitespace, not just a space. The value is
		// appended rather than dropped so that a multi-line field cannot be
		// mistaken for the start of a new stanza.
		if line[0] == ' ' || line[0] == '\t' {
			if last != "" {
				fields[last] += " " + strings.TrimSpace(line)
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			// Not a field and not a continuation. dpkg would refuse the file;
			// this skips the line, because a status file with one odd line is
			// far more likely than a scan that should fail — and the packages
			// around it are still worth reporting.
			continue
		}
		// Whitespace before the colon is legal, and field names are compared
		// case-insensitively.
		key := strings.ToLower(strings.TrimSpace(name))
		fields[key] = strings.TrimSpace(value)
		last = key
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

// toPackage converts one stanza. ok is false for a stanza that names no package
// or whose Status says its files are not on disk.
func toPackage(f map[string]string, ecosystem, path string) (pkgmeta.Package, bool, error) {
	name := f["package"]
	if name == "" {
		// A stanza with no Package is not a package. status.d directories carry
		// sibling files (*.md5sums) that parse as stanzas of nothing.
		return pkgmeta.Package{}, false, nil
	}
	if st, ok := f["status"]; ok && !isInstalled(st) {
		return pkgmeta.Package{}, false, nil
	}
	// An ABSENT Status means installed. Every package in a distroless image is
	// in that state — its stanzas carry no Status field at all — and treating
	// absence as "not installed" would report those images as having no
	// packages, which is a clean verdict for a scan that checked nothing.
	// dpkg writes no Version for a not-installed stanza. Emitted empty rather
	// than dropped or invented: the matcher already reports a package with no
	// usable version as unevaluable, and that is a loud answer where dropping
	// it would be a silent one.
	version := f["version"]

	p := pkgmeta.Package{
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
		Locations: []pkgmeta.Location{{Path: path}},
	}
	p.Source = sourceOf(f, name, version)
	return p, true, nil
}

// sourceOf reads the Source field's three forms (D8, and D41 for the version).
//
// Measured across debian:bookworm, debian:trixie-slim, ubuntu:24.04 and
// ubuntu:22.04: the field is absent for 26-29% of packages, a bare name for
// 60-71%, and "name (version)" for 1-15%. The last form is where Debian and
// Ubuntu diverge — Debian binNMUs (bash 5.2.15-2+b13 from source 5.2.15-2)
// while Ubuntu rebuilds with a new revision — so a fixture built only on Ubuntu
// would exercise it about once.
//
// Absent means the source name and version are the binary's own, which is what
// dpkg-gencontrol omits the field to say. Filling both in rather than leaving
// them empty is what lets the matcher treat every ecosystem the same way.
func sourceOf(f map[string]string, name, version string) *pkgmeta.SourcePackage {
	raw := f["source"]
	if raw == "" {
		return &pkgmeta.SourcePackage{Name: name, Version: version}
	}
	srcName, rest, hasVersion := strings.Cut(raw, " ")
	src := &pkgmeta.SourcePackage{Name: srcName, Version: version}
	if hasVersion {
		if v, ok := strings.CutPrefix(strings.TrimSpace(rest), "("); ok {
			if v, ok := strings.CutSuffix(v, ")"); ok && v != "" {
				src.Version = v
			}
		}
	}
	return src
}

// isInstalled reads the THIRD word of Status and nothing else.
//
// The first word is a future intent ("deinstall" means somebody asked for
// removal, not that it happened) and the second is an error marker. Matching on
// either is how syft drops "deinstall ok installed" and trivy drops
// "purge ok installed" — both packages whose files are still on disk.
func isInstalled(status string) bool {
	fields := strings.Fields(status)
	if len(fields) != 3 {
		// Not the three-word grammar. Treated as installed for the same reason
		// an absent Status is: refusing to report a package because its state
		// field is shaped oddly is a silent miss.
		return true
	}
	return installedStates[fields[2]]
}
