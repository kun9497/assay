// Package pacmandb turns Arch Linux's pacman local package database into the
// normalized inventory (D97).
//
// Unlike apk (one flat file, many stanzas) or dpkg (one flat file, or
// status.d's one-stanza-per-file for distroless images, D54), pacman's own
// local database is one DIRECTORY PER INSTALLED PACKAGE --
// /var/lib/pacman/local/<name>-<version>-<pkgrel>/desc -- so this cataloger
// reads one package per call, the same shape dpkgdb.ParseStanza already
// established for distroless images. The directory also carries a sibling
// file, ALPM_DB_VERSION, which is not a package directory and not shaped
// like a desc file at all; discovering which entries under local/ ARE
// package directories is the image-scan layer's job
// (internal/scancmd, via source.FilesNamed), not this package's -- ParseDesc
// only has to tolerate being handed something that is not a desc file
// without inventing a package out of it.
//
// The desc file's own grammar: "%SECTION%\n" followed by one or more value
// lines, sections separated by a blank line -- MEASURED verbatim against a
// real image (mirror.gcr.io/library/archlinux, pulled 2026-08-26; see this
// package's testdata for the captures). Most sections are single-valued
// (%NAME%, %VERSION%, %BASE%, %ARCH%, all read here), but %DEPENDS% and a
// multi-license %LICENSE% carry one value per line (measured on bash's own
// desc: DEPENDS lists readline, libreadline.so=8-64, glibc, ncurses on four
// separate lines; gcc-libs' own desc carries two LICENSE lines) -- neither
// section is read by this cataloger, but the parser below tolerates the
// shape rather than assuming one value per section, since a value that
// happened to start a new "record" at the wrong line would corrupt every
// field read after it.
//
// D8's exact analogue: %BASE% is the pkgbase Arch's own security tracker
// writes advisories against (internal/provider/arch), and it differs from
// %NAME% for split packages -- measured 25/137 (18.2%) of a real image's
// installed packages, including six (elfutils, gcc, lvm2, nss, openldap,
// sysprof) whose advisories are reachable ONLY through their base name (a
// libelf CVE, say, is filed against elfutils, never against libelf).
// Populated only when BASE differs from NAME, unlike apkdb's unconditional
// read of apk's `o:` origin: pacman's BASE is present on every record, even
// non-split ones where it simply repeats NAME (measured: every one of 137
// installed packages carries a %BASE% section), and storing it there too
// would make --explain's D8 wording ("matched via source package") print
// for a package whose "source" is itself.
//
// %PROVIDES% is deliberately NOT read here. D95's provides bridge
// (pkgmeta.Package.Provides) is apk-only by design -- its own doc comment
// says so -- and Arch's advisories key on pkgbase, which Source already
// covers; there is no BellSoft-Alpaquita-shaped third name here that only a
// sibling package's provides clause could reach.
package pacmandb

import (
	"bufio"
	"io"
	"strings"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// ParseDesc reads one pacman database entry -- the desc file at
// /var/lib/pacman/local/<name>-<version>-<pkgrel>/desc -- and returns the
// package it names.
//
// A slice, not a single Package plus an ok bool: one desc file names zero
// packages (not a desc file at all -- ALPM_DB_VERSION's own content, or
// anything else that reached this function without a %NAME% section) or
// one, never more, but a slice return lets the image-scan caller append
// this cataloger's result the exact same way it already appends
// dpkgdb.ParseStanza's (D54's convention), with no second branch for this
// cataloger's shape.
//
// ecosystem is supplied by the caller (Distro.Ecosystem(), "Arch:rolling")
// -- a bare desc file cannot know its own distro (D6, D7), even though
// Arch's own key carries no release axis to get wrong (D97). path is
// recorded on the Location for evidence (D10) -- normally the desc file's
// own tar path, so a report can point back at exactly which file named the
// package.
func ParseDesc(r io.Reader, ecosystem, path string) ([]pkgmeta.Package, error) {
	fields, err := parseSections(r)
	if err != nil {
		return nil, err
	}
	name := firstValue(fields, "NAME")
	if name == "" {
		// No %NAME% section means this was never a package record. Emitting
		// one anyway would hand the matcher a lookup key of "" that can only
		// ever miss -- a silent false negative, not a harmless empty entry
		// (apkdb.Parse's own reasoning for the identical guard).
		return nil, nil
	}

	p := pkgmeta.Package{
		Name:      name,
		Version:   firstValue(fields, "VERSION"),
		Type:      "alpm", // syft's own purl type for pacman/libalpm packages
		Ecosystem: ecosystem,
		Locations: []pkgmeta.Location{{Path: path}},
	}
	if base := firstValue(fields, "BASE"); base != "" && base != name {
		// D8, D97: only Name is set, never Version -- like apk's origin, a
		// split package's base carries no version of its own; the comparer
		// uses the binary's own Version above, not BASE's.
		p.Source = &pkgmeta.SourcePackage{Name: base}
	}
	return []pkgmeta.Package{p}, nil
}

// firstValue returns a section's first value line, or "" if the section is
// absent or empty. Every section this cataloger reads (%NAME%, %VERSION%,
// %BASE%) is single-valued in practice; the multi-value sections
// (%DEPENDS%, a multi-license %LICENSE%) are never read through this
// helper.
func firstValue(fields map[string][]string, key string) string {
	vs := fields[key]
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// parseSections reads a desc file's "%SECTION%\nvalue\nvalue\n\n" blocks
// into a section -> values map.
//
// Values are appended one per line until a blank line (or the next
// %SECTION% header) ends the current section -- %DEPENDS% and a
// multi-license %LICENSE% both carry more than one value this way on a real
// image (measured against bash's and gcc-libs' own desc files, this
// package's testdata). A line seen before any %SECTION% header, or a blank
// line with no section open, is simply skipped: a desc file always opens
// with %NAME%, so this only matters for a malformed or truncated file, and
// dropping a line the format does not explain is the same discipline
// dpkgdb.parseStanzas applies to a status-file line with no colon in it.
func parseSections(r io.Reader) (map[string][]string, error) {
	fields := map[string][]string{}
	var key string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			key = ""
			continue
		}
		if isSectionHeader(line) {
			key = line[1 : len(line)-1]
			continue
		}
		if key != "" {
			fields[key] = append(fields[key], line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return fields, nil
}

// isSectionHeader reports whether line is a "%WORD%" section marker: at
// least one byte between two '%' delimiters, so a bare "%%" (which would
// slice to an empty key) does not count.
func isSectionHeader(line string) bool {
	return len(line) > 2 && strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%")
}
