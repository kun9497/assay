// Package osrelease turns /etc/os-release into a pkgmeta.Distro.
//
// This is where the OSV ecosystem key starts: pkgmeta.Distro.Ecosystem()
// truncates VersionID into "Alpine:v3.19" and is what every Alpine package in
// the image gets looked up under. This package's only job is filling the
// three fields correctly — the truncation and validation live on Distro.
package osrelease

import (
	"bufio"
	"io"
	"strings"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// Parse reads an os-release file and returns the fields pkgmeta.Distro needs.
//
// Only ID, VERSION_ID, and PRETTY_NAME are read; every other key is ignored
// rather than rejected. The file carries vendor and URL fields (NAME,
// HOME_URL, BUG_REPORT_URL, ...) that vary by distro, and erroring on an
// unrecognized key would make this fail on every distro but the one it was
// tested against.
//
// A file with none of the three keys yields a zero Distro and no error:
// deciding what an unidentifiable distro means is the caller's job, and
// Distro.Ecosystem() already refuses to key an empty ID. Likewise a line that
// is not shaped like KEY=VALUE — blank, a comment, or otherwise malformed —
// is skipped rather than treated as a parse failure, for the same reason: the
// shape of one stray line says nothing about whether the rest of the file is
// trustworthy.
//
// The comment-line check and the exact key match below are mutually
// redundant: a "#"-prefixed line can never produce a key equal to ID,
// VERSION_ID, or PRETTY_NAME, since the "#" is always part of the substring
// strings.Cut returns as the key. Neither guard is individually observable by
// a black-box test of Parse, so a later refactor that "simplifies" one away
// will not be caught by one — keep both anyway, since removing either changes
// nothing about correctness today but removes a safety margin against a
// future change to the key match (e.g. a case-insensitive or prefix match)
// that would make the missing guard observable again.
func Parse(r io.Reader) (pkgmeta.Distro, error) {
	var d pkgmeta.Distro

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		switch strings.TrimSpace(key) {
		case "ID":
			d.ID = unquote(value)
		case "VERSION_ID":
			d.VersionID = unquote(value)
		case "PRETTY_NAME":
			d.PrettyName = unquote(value)
		}
	}
	if err := sc.Err(); err != nil {
		return pkgmeta.Distro{}, err
	}
	return d, nil
}

// unquote strips one layer of matching quotes the way a shell would when
// sourcing this file. Quoting is inconsistent even within a single real
// file — VERSION_ID is bare while PRETTY_NAME is quoted in the alpine:3.19
// image this was built against — so both the quoted and bare forms have to be
// handled unconditionally, never assumed from one key to the next.
func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
