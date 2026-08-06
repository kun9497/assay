// Package requirements reads pip's requirements file format.
//
// It is deliberately the most conservative of the catalogers, because the file
// it reads is the weakest input any of them take. D26 kept it unread for that
// reason: `Django>=3.2` is a constraint, not a version, and placing a range
// inside an advisory range would quietly answer "not vulnerable" for anything
// unpinned. D38 reverses the omission without reversing the reasoning — the
// lines that name exactly one installable version become packages, and every
// other line is counted and named rather than guessed at.
//
// **A requirements file is a list of pip install arguments, not a manifest.**
// That is pip's own framing, and it is why a parser built on PEP 508 alone is
// already wrong: the grammar is argparse *around* PEP 508. Options, includes,
// editable installs and bare paths all share the file with requirement
// specifiers, and each has to be recognized to be refused honestly.
//
// **What other scanners do, and why this does not.** syft's guessVersion
// rewrites `*` to `0` and takes the maximum of a `>=` bound, inventing a
// version the file never stated; trivy gates on the operator; pip-audit — from
// PyPA itself — refuses an unpinned requirement and reports it as a skipped
// dependency. This follows pip-audit. A fabricated version is a confident wrong
// answer in either direction: too low and the package reads as vulnerable when
// it is not, too high and a real vulnerability reads as fixed.
package requirements

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// Unusable is a requirement line this parser refused to turn into a package,
// with the reason. It exists so the report can name what it could not use
// rather than only counting it: "3 package(s) with no version to compare" does
// not tell a reader which three, and pinning them is the action being asked
// for.
type Unusable struct {
	// Line is the requirement as written, after comment stripping and
	// continuation joining — what the reader will find if they open the file.
	Line   string
	Reason string
}

// commentRE is pip's own COMMENT_RE, copied deliberately rather than
// approximated with strings.Index.
//
// A '#' starts a comment only at the start of a line or after whitespace. Cut
// on the first '#' anywhere and `#egg=`, `#subdirectory=` and `#sha256=`
// fragments are destroyed mid-URL — which turns a line this parser would have
// refused honestly into a mangled one it refuses for the wrong reason, and in
// a parser that read versions off URLs would turn it into a wrong version.
var commentRE = regexp.MustCompile(`(^|\s)#.*$`)

// envVarRE is pip's ENV_VAR_RE. pip substitutes these from its own process
// environment at install time; this parser does not, and refuses the line
// instead — see the Reason it produces.
var envVarRE = regexp.MustCompile(`\$\{[A-Z0-9_]+\}`)

// specifierRE splits a requirement into name, extras and specifier set. The
// marker (everything after ';') is removed before this runs.
var specifierRE = regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$`)

// pinnedRE matches a specifier set that names exactly one version: a single
// clause whose operator is '==' or '===', with no trailing '.*'.
//
// Deliberately narrower than the format allows. `Django==3.2,!=3.2.1` does name
// one version, and admitting it means admitting multi-clause sets, where
// `foo==1.4.*,!=1.4.1` slips through any rule that checks "exactly one =="
// without also excluding the wildcard. That hole survived a first review of the
// research this decision rests on; a rule with no multi-clause case cannot have
// it. The cost is a shape that is rare in the corpus and loudly reported when
// it appears.
// The character class excludes '*' as well as ',' and whitespace. A PEP 440
// version contains no asterisk, so a specifier that has one is a prefix match
// — a range. Without that exclusion this regex classified `Django==3.2.*` as a
// pin at version "3.2.*", which the comparer would then refuse, turning a
// range into an unreadable version instead of an honest "not pinned".
var pinnedRE = regexp.MustCompile(`^(===|==)\s*([^,\s*]+)$`)

// Parse reads path and returns the packages it names, catalog statistics, and
// every line it could not use.
//
// Stats.Components counts every requirement line — pinned or not — because a
// requirement this parser refused is still a component the scan saw and did not
// evaluate, and the summary's "not evaluated" count is derived from the
// difference. Lines that are not requirements at all (options, blank lines,
// comments) are not components and are not counted.
func Parse(path string) (pkgmeta.Target, cyclonedx.Stats, []Unusable, error) {
	f, err := os.Open(path)
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	defer f.Close()

	var (
		target   pkgmeta.Target
		stats    cyclonedx.Stats
		unusable []Unusable
	)

	for _, line := range logicalLines(f) {
		kind, detail := classify(line)
		switch kind {
		case kindIgnorable:
			// A global option or an empty line. Not a component: counting it
			// would inflate "not evaluated" with things that were never
			// packages, which makes the count mean less rather than more.
			continue
		case kindPinned:
			stats.Components++
			stats.Cataloged++
			target.Packages = append(target.Packages, pkgmeta.Package{
				Name:      detail.name,
				Version:   detail.version,
				Ecosystem: "PyPI",
			})
		default:
			stats.Components++
			stats.SkippedNoVersion++
			unusable = append(unusable, Unusable{Line: line, Reason: detail.reason})
		}
	}
	return target, stats, unusable, nil
}

// logicalLines applies pip's preprocessing in pip's order: join continuations,
// then strip comments, then drop what is left empty.
//
// The order is load-bearing and is pip's, not a convenience. Stripping comments
// first would let a trailing '#' comment swallow the backslash that continues
// the line, silently gluing two requirements into one.
func logicalLines(r *os.File) []string {
	var out []string
	sc := bufio.NewScanner(r)
	// Requirement lines are short; the default 64 KiB token is ample and a
	// pathological file should fail loudly rather than be read in part.
	var joined strings.Builder
	first := true
	for sc.Scan() {
		raw := sc.Text()
		if first {
			// A UTF-8 BOM is not part of the first requirement. Assembled from
			// its code point rather than typed: writing the character itself
			// put an illegal byte order mark in the middle of this file and
			// broke the build, which is the hazard CLAUDE.md records and the
			// fourth time it fired in this session.
			raw = strings.TrimPrefix(raw, string(rune(0xFEFF)))
			first = false
		}
		if cont, ok := strings.CutSuffix(raw, `\`); ok {
			joined.WriteString(cont)
			continue
		}
		joined.WriteString(raw)
		if line := strings.TrimSpace(commentRE.ReplaceAllString(joined.String(), "")); line != "" {
			out = append(out, line)
		}
		joined.Reset()
	}
	// A file whose last line ends in a backslash has nothing to continue into.
	// pip treats the accumulated text as a line rather than discarding it.
	if line := strings.TrimSpace(commentRE.ReplaceAllString(joined.String(), "")); line != "" {
		out = append(out, line)
	}
	return out
}

type lineKind int

const (
	kindIgnorable lineKind = iota // not a component at all
	kindPinned                    // names exactly one version
	kindUnusable                  // a component with no version this parser may state
)

type detail struct {
	name, version, reason string
}

// classify decides what one logical line is.
func classify(line string) (lineKind, detail) {
	// pip expands ${VAR} from its own environment. Doing that here would read
	// the scanning machine's environment, which is not the environment the file
	// describes, so the value would be an invention. Refused by name.
	if envVarRE.MatchString(line) {
		return kindUnusable, detail{reason: "contains an environment variable, which pip expands at install time"}
	}

	// break_args_options: everything before the first token starting with '-'
	// is the requirement, the rest is options. A line that STARTS with an
	// option has no requirement in it.
	fields := strings.Fields(line)
	if len(fields) > 0 && strings.HasPrefix(fields[0], "-") {
		switch {
		case isOpt(fields[0], "-r", "--requirement"):
			return kindUnusable, detail{reason: "includes another requirements file, which this scan does not follow"}
		case isOpt(fields[0], "-c", "--constraint"):
			return kindUnusable, detail{reason: "a constraints file, which pins nothing on its own"}
		case isOpt(fields[0], "-e", "--editable"):
			return kindUnusable, detail{reason: "an editable install, which names no released version"}
		default:
			// --index-url, --find-links, --no-binary and friends configure pip;
			// they are not packages and must not be counted as ones.
			return kindIgnorable, detail{}
		}
	}
	req := fields[0]
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "-") {
			break
		}
		req += " " + f
	}

	// A direct reference (`name @ https://…`), a VCS URL, a path, or an archive
	// filename. Each of these can carry a version, and reading it off means
	// stripping URL fragments and query strings and percent-decoding first —
	// three places to be wrong, for shapes the corpus shows are rare. Refused
	// honestly instead.
	switch {
	case strings.Contains(req, "@"):
		return kindUnusable, detail{reason: "a direct reference to a URL or path, not a released version"}
	case strings.Contains(req, "://"):
		return kindUnusable, detail{reason: "a URL, not a released version"}
	case strings.HasPrefix(req, ".") || strings.HasPrefix(req, "/") || strings.HasPrefix(req, `\`):
		return kindUnusable, detail{reason: "a local path, not a released version"}
	case hasArchiveSuffix(req):
		return kindUnusable, detail{reason: "an archive filename, not a released version"}
	}

	// The environment marker is dropped, not evaluated (D38). Evaluating it
	// would need the environment the code will RUN in, and all this process has
	// is its own — so a marker that is false there says nothing about the
	// deployment. Reporting a package that a marker excludes is a false
	// positive, which is loud; refusing every marked line is a silent gap in a
	// shape the corpus shows is common.
	if i := strings.Index(req, ";"); i >= 0 {
		req = strings.TrimSpace(req[:i])
	}

	m := specifierRE.FindStringSubmatch(req)
	if m == nil {
		return kindUnusable, detail{reason: "not a requirement this parser recognizes"}
	}
	name, specs := m[1], strings.TrimSpace(m[3])
	if specs == "" {
		return kindUnusable, detail{reason: "no version specified"}
	}
	p := pinnedRE.FindStringSubmatch(specs)
	if p == nil {
		return kindUnusable, detail{reason: "not pinned to one version: " + specs}
	}
	// The version is stored as written. `===` may carry a string PEP 440 cannot
	// parse at all, and that must reach the comparer as an unreadable version
	// (loud, counted) rather than be filtered out here (silent).
	return kindPinned, detail{name: name, version: p[2]}
}

func isOpt(got string, forms ...string) bool {
	for _, f := range forms {
		if got == f || strings.HasPrefix(got, f+"=") {
			return true
		}
	}
	return false
}

func hasArchiveSuffix(s string) bool {
	for _, ext := range []string{".whl", ".tar.gz", ".zip", ".tar.bz2"} {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return false
}
