// Package apkdb turns /lib/apk/db/installed into the normalized inventory.
//
// This is where D8 actually starts mattering for Alpine: apk's "origin" field
// (o:) is the source package an advisory may be keyed on, and it is populated
// here, at catalog time, exactly as it is from cyclonedx's
// syft:metadata:originPackage property. Nothing downstream — matcher, store,
// comparer — changes for this being a different Cataloger.
package apkdb

import (
	"bufio"
	"io"
	"strings"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// installedPath is recorded on every Location produced here. It never varies
// per package — this whole cataloger only ever reads one file — so it is a
// constant rather than something threaded through every call.
const installedPath = "/lib/apk/db/installed"

// record is the subset of one apk-db record this cataloger reads. Keeping
// architecture here even though pkgmeta.Package has no field for it is what
// makes the case-sensitivity dispatch below testable in isolation: without
// it, the A:/a: collision this format invites would only be observable by
// accident, if a file's permission string happened to overwrite a field
// Package actually exposes.
type record struct {
	name    string // P: package name
	version string // V: package version
	arch    string // A: architecture — recorded, but never part of a lookup key
	origin  string // o: origin/source package (D8)
}

// Parse reads an apk installed-database (/lib/apk/db/installed) and returns
// the packages it names.
//
// ecosystem is supplied by the caller — Distro.Ecosystem(), e.g. "Alpine:v3.19"
// — rather than derived here, because a bare package record cannot know its
// distro's release (D6, D7): the same apk record means a different set of
// fixed versions on 3.18 versus 3.19.
func Parse(r io.Reader, ecosystem string) ([]pkgmeta.Package, error) {
	recs, err := parseRecords(r)
	if err != nil {
		return nil, err
	}

	pkgs := make([]pkgmeta.Package, 0, len(recs))
	for _, rec := range recs {
		if rec.name == "" {
			// No P: line means this was never a package record. Emitting one
			// anyway would hand the matcher a lookup key of "" that can only
			// ever miss — a silent false negative, not a harmless empty entry.
			continue
		}
		pkgs = append(pkgs, toPackage(rec, ecosystem))
	}
	return pkgs, nil
}

func toPackage(rec record, ecosystem string) pkgmeta.Package {
	p := pkgmeta.Package{
		Name:      rec.name,
		Version:   rec.version,
		Type:      "apk",
		Ecosystem: ecosystem,
		Locations: []pkgmeta.Location{{Path: installedPath}},
	}
	if rec.origin != "" {
		// D8: only Name is set. Alpine binary packages carry their source
		// package's own version, so SourcePackage.Version staying empty is
		// correct here, not a gap — the comparer uses rec.version above.
		p.Source = &pkgmeta.SourcePackage{Name: rec.origin}
	}
	return p
}

// parseRecords splits the file on blank lines and reads the four fields this
// cataloger cares about from each block.
//
// Records are separated by a blank line; the real fixture also ends with one,
// and a doubled blank line between two records is legal too — both are just
// "no fields since the last flush" and must not fabricate an empty record.
//
// Every line is <letter>:<value>. Keys are case-sensitive on purpose: A
// (architecture) and a (a file's owner/permission triple) are unrelated
// fields that happen to share a letter, and so are T (description) and t
// (build timestamp) — 'P' (name) and 'p' (provides) is the pair that matters
// most, since 'p' sits later in this file's own field order and a
// case-folded dispatch would let a provides-clause line overwrite the name a
// P: line already set. In the real fixture file-level fields (a, F, R, Z, M)
// outnumber package-level ones roughly 5:1, so this is the common line, not
// the edge case. Dispatch happens on the raw first byte of the key, never on
// a case-folded copy of it.
func parseRecords(r io.Reader) ([]record, error) {
	var (
		recs []record
		cur  record
	)

	flush := func() {
		recs = append(recs, cur)
		cur = record{}
	}

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok || key == "" {
			// Not a <letter>:<value> line. Skipped rather than treated as a
			// parse failure: one stray line says nothing about whether the
			// rest of the file is trustworthy, the same reasoning osrelease
			// applies to its own malformed lines.
			continue
		}

		switch key[0] {
		case 'P':
			cur.name = value
		case 'V':
			cur.version = value
		case 'A':
			cur.arch = value
		case 'o':
			cur.origin = value
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// The last record has no trailing blank line to trigger a flush unless
	// the producer added one (the real fixture does). Flushing unconditionally
	// after the loop is safe either way: a file that already ended on a blank
	// line leaves cur zeroed, and Parse already treats a zero-value record
	// (no P: line) as "not a package" — the same rule a doubled blank line's
	// phantom empty block needs, so no separate handling belongs here.
	flush()
	return recs, nil
}
