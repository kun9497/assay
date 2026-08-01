// Package gomod turns a go.mod file into the normalized package inventory,
// using nothing but the standard library (D23). It is a directory cataloger,
// not a build-list cataloger: it reports what the module requires, not what a
// build would actually link, and it never invokes the go tool or reads
// go.sum, so - unlike `go list -m all` - it makes no network call and needs
// no module cache.
package gomod

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// requirement is one `require` entry: a module path and the version go.mod
// asked for. Either field may be empty - path when a quoted path could not be
// resolved, version when the line was missing it - and an empty version is
// what routes the entry to a counted skip rather than a fabricated package.
type requirement struct {
	path    string
	version string
}

// replacement is the right-hand side of a `replace` directive.
type replacement struct {
	path    string
	version string
	// filesystem is true when the right-hand side names a directory rather
	// than a module - `replace A => ../local` - which carries no version to
	// compare against any advisory range.
	filesystem bool
}

// Parse reads <dir>/go.mod and returns the modules it requires, after
// applying replace directives. Distro stays nil - a Go module is not a distro
// (D7); Package.Source stays nil - D8's source/binary split is a distro
// concern and Go has none.
func Parse(dir string) (pkgmeta.Target, cyclonedx.Stats, error) {
	path := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(path)
	if err != nil {
		// No extra path text added here: os.ReadFile's own error already
		// names the full path - both dir and "go.mod" - so wrapping it again
		// would only double it up. TestParse_NoGoModIsAnError still fails if
		// a future Go version ever stops naming the path in its own error.
		return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("read go.mod: %w", err)
	}

	requires, replaceAny, replaceExact, err := directives(data)
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", path, err)
	}

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
	)
	for _, r := range requires {
		stats.Components++

		name, version := r.path, r.version
		if rep, ok := lookupReplace(r, replaceAny, replaceExact); ok {
			if rep.filesystem {
				name, version = "", ""
			} else {
				name, version = rep.path, rep.version
			}
		}

		if version == "" {
			// Not a version any comparer can place inside a range - a
			// filesystem replace's right-hand side, a require line missing
			// its version field, or a module path this scan could not
			// resolve (a quoted path split apart by an internal space, most
			// likely). Counting it as cataloged would claim it was
			// evaluated when it was not; dropping it silently would remove
			// it from the inventory without removing it from the count of
			// what was seen.
			stats.SkippedNoVersion++
			continue
		}

		stats.Cataloged++
		pkgs = append(pkgs, pkgmeta.Package{
			Name:      name,
			Version:   version,
			Type:      "golang",
			Ecosystem: "Go",
			PURL:      "pkg:golang/" + name + "@" + version,
			Locations: []pkgmeta.Location{{Path: path}},
		})
	}

	return pkgmeta.Target{Packages: pkgs}, stats, nil
}

// lookupReplace resolves the replace directive that applies to r, if any.
// A version-qualified replace (`replace A v1.0.0 => ...`) is checked first
// because it is the more specific directive; an unqualified one
// (`replace A => ...`) applies to whatever version A was required at.
func lookupReplace(r requirement, replaceAny, replaceExact map[string]replacement) (replacement, bool) {
	if rep, ok := replaceExact[r.path+"@"+r.version]; ok {
		return rep, true
	}
	rep, ok := replaceAny[r.path]
	return rep, ok
}

// isBlockDirective reports whether keyword is one of the four directives
// that accept a `keyword ( ... )` block form.
func isBlockDirective(keyword string) bool {
	switch keyword {
	case "require", "replace", "exclude", "retract":
		return true
	default:
		return false
	}
}

// directives scans go.mod line by line and collects every require and
// replace directive. go.mod is line-oriented: require, replace, exclude and
// retract each have a single-line form and a `keyword ( ... )` block form, so
// blockKind tracks which directive - if any - the current line is inside.
//
// A malformed replace directive, an unterminated block, or a block opened
// while another is already open are all reported as an error rather than
// guessed at: each would otherwise either fabricate a package (a directive
// keyword misread as a module path) or silently redirect nothing while the
// replaced-away module keeps reporting as itself - a false positive on code
// that is not there, paired with a silent false negative on the code that is.
func directives(data []byte) (requires []requirement, replaceAny, replaceExact map[string]replacement, err error) {
	replaceAny = map[string]replacement{}
	replaceExact = map[string]replacement{}

	blockKind := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" {
			continue
		}

		if blockKind != "" {
			if line == ")" {
				blockKind = ""
				continue
			}
			// Blocks do not nest in go.mod. A line that itself looks like it
			// is opening another directive block would otherwise be parsed
			// as an ordinary body line - fabricating a package named after
			// the keyword (e.g. "exclude"@"(") - and then close the OUTER
			// block early on the next ")". Neither degradation is safe, so
			// this is reported rather than guessed at.
			if k, r := splitKeyword(line); isBlockDirective(k) && strings.TrimSpace(r) == "(" {
				return nil, nil, nil, fmt.Errorf("go.mod: %q opens a block while a %s block is still open", line, blockKind)
			}
			if aerr := apply(blockKind, line, &requires, replaceAny, replaceExact); aerr != nil {
				return nil, nil, nil, aerr
			}
			continue
		}

		keyword, rest := splitKeyword(line)
		switch keyword {
		case "require", "replace", "exclude", "retract":
			rest = strings.TrimSpace(rest)
			if rest == "(" {
				blockKind = keyword
				continue
			}
			if strings.HasPrefix(rest, "(") {
				// A block's opening line is always the keyword alone
				// followed by "(" and nothing else (a trailing comment
				// aside, already stripped by now). Content crammed onto
				// the same line - `require(path version)` - is not valid
				// go.mod; go itself rejects it. Falling through to
				// ordinary single-line parsing would fabricate a package
				// from the mangled remainder (a leading "(" stuck to the
				// path, a trailing ")" stuck to the version) instead of
				// refusing it.
				return nil, nil, nil, fmt.Errorf("go.mod: malformed %s directive: %q", keyword, line)
			}
			if aerr := apply(keyword, rest, &requires, replaceAny, replaceExact); aerr != nil {
				return nil, nil, nil, aerr
			}
		default:
			// module, go, toolchain, and anything else this parser does not
			// recognize (godebug, tool, ...) name no package. In particular
			// `go 1.26` and `toolchain go1.26.4` are a language floor and a
			// build request, not a fact about any artifact (D24) - reporting
			// either as a package would claim a version nothing was ever
			// built with.
		}
	}
	if serr := scanner.Err(); serr != nil {
		return nil, nil, nil, serr
	}
	if blockKind != "" {
		// EOF with a block still open - a truncated or conflict-mangled
		// go.mod. Left unchecked, every directive that follows (a module
		// line, `go`, `toolchain`, another require) would be swallowed as a
		// body line of the still-open block and parsed as a `path version`
		// pair - reproducing the D24 mistake (`go` reported as a package)
		// from a broken file rather than a code bug.
		return nil, nil, nil, fmt.Errorf("go.mod: unterminated %s ( ... ) block", blockKind)
	}
	return requires, replaceAny, replaceExact, nil
}

// apply processes one directive body: either the remainder of a single-line
// directive, or one line inside a `keyword ( ... )` block. A block line
// carries no keyword of its own, so both forms share this parsing.
func apply(keyword, body string, requires *[]requirement, replaceAny, replaceExact map[string]replacement) error {
	switch keyword {
	case "require":
		fields := strings.Fields(body)
		var path, version string
		if len(fields) >= 1 {
			if p, ok := parseModulePath(fields[0]); ok {
				path = p
				if len(fields) >= 2 {
					version = fields[1]
				}
			}
			// If the path itself could not be resolved - most likely a
			// quoted path split apart by an internal space this
			// whitespace-based scan cannot see across - version is left
			// empty too, so the entry is skipped uniformly by Parse rather
			// than cataloged under a name with a stray leading quote.
		}
		*requires = append(*requires, requirement{path: path, version: version})

	case "replace":
		oldPath, oldVersion, rep, outcome := parseReplace(body)
		switch outcome {
		case replaceMalformed:
			// A replace directive whose shape cannot be recognized (no
			// "=>", or a right-hand side that is neither one field nor two,
			// and not a quoted value split apart by whitespace) is not a
			// case this scan can degrade safely from: the require entry it
			// was meant to redirect would otherwise keep reporting as
			// itself, unreplaced - a false positive on code that is not
			// there, paired with a silent miss of the code that is.
			return fmt.Errorf("go.mod: malformed replace directive: %q", body)
		case replaceUnkeyed:
			// The left-hand module path itself could not be resolved, so
			// there is no key to register a replacement under. Not an
			// error - the real go tool accepts a quoted path containing a
			// space - and not a false positive either: the require line
			// (if any) for that same malformed path already degrades to
			// its own counted skip independently, the same way F4 handles
			// an unresolvable require path.
		case replaceOK:
			if oldVersion == "" {
				replaceAny[oldPath] = rep
			} else {
				replaceExact[oldPath+"@"+oldVersion] = rep
			}
		}

	case "exclude", "retract":
		// Neither changes what is linked into a build: exclude removes one
		// version from consideration during resolution, retract is a
		// module author's advisory against its own past release. Nothing to
		// report from either.
	}
	return nil
}

// replaceOutcome classifies what parseReplace determined about one replace
// directive body.
type replaceOutcome int

const (
	// replaceMalformed: the directive's shape could not be recognized at
	// all - no "=>", or a right-hand side that is neither one field nor
	// two, with no quoted value split by whitespace to blame it on. Not
	// safe to fall through: the require entry it was meant to redirect
	// would otherwise keep reporting as itself, unreplaced.
	replaceMalformed replaceOutcome = iota
	// replaceUnkeyed: the left-hand module path itself could not be
	// resolved - almost always a quoted path containing an internal space,
	// split apart by this scan's whitespace-based field splitting before
	// the quote is ever seen as one token. There is no key to register a
	// replacement under, so this directive contributes nothing - not an
	// error, since the real go tool accepts this file.
	replaceUnkeyed
	// replaceOK: oldPath/oldVersion/rep are valid and should be registered.
	replaceOK
)

// parseReplace splits a replace directive body on "=>". The right-hand
// side's field count decides its shape: two fields is a module and a
// version, one field is a filesystem path with no version. oldVersion is
// empty when the left-hand side named no version (an unqualified replace).
//
// A quoted value containing an internal space - most often a filesystem
// path like "../my dir" or "C:\Users\John Doe" - is split apart by this
// scan's whitespace-based field splitting before the quote is ever seen as
// one token, on either side of "=>". The real go tool accepts such a file
// (a local replace into a path containing a space is ordinary on Windows),
// so this is deliberately NOT folded into replaceMalformed: the affected
// side degrades to replaceUnkeyed (left) or a filesystem replacement
// (right, since its value is discarded either way - Parse never uses it).
func parseReplace(body string) (oldPath, oldVersion string, rep replacement, outcome replaceOutcome) {
	parts := strings.SplitN(body, "=>", 2)
	if len(parts) != 2 {
		return "", "", replacement{}, replaceMalformed
	}

	left := strings.Fields(parts[0])
	if len(left) == 0 {
		return "", "", replacement{}, replaceMalformed
	}
	oldPath, pathOK := parseModulePath(left[0])
	if !pathOK {
		return "", "", replacement{}, replaceUnkeyed
	}
	if len(left) >= 2 {
		oldVersion = left[1]
	}

	right := strings.Fields(parts[1])
	if len(right) == 0 {
		return "", "", replacement{}, replaceMalformed
	}
	if looksQuoted(right[0]) {
		return oldPath, oldVersion, replacement{filesystem: true}, replaceOK
	}
	switch len(right) {
	case 1:
		return oldPath, oldVersion, replacement{filesystem: true}, replaceOK
	case 2:
		newPath, newPathOK := parseModulePath(right[0])
		if !newPathOK {
			return "", "", replacement{}, replaceMalformed
		}
		return oldPath, oldVersion, replacement{path: newPath, version: right[1]}, replaceOK
	default:
		return "", "", replacement{}, replaceMalformed
	}
}

// looksQuoted reports whether field opens a go.mod quoted string but does
// not close within the same whitespace-delimited token - the signature of a
// value containing an internal space, split apart by this scan's naive
// field splitting before the quote is ever seen as one token. Checked
// separately from parseModulePath's own failure so a replace's right-hand
// side can tell "split by whitespace" (recoverable as a filesystem
// replacement - the value is discarded anyway) apart from "closes cleanly
// but is otherwise unusable" (a genuine malformation).
func looksQuoted(field string) bool {
	return len(field) > 0 && field[0] == '"' && (len(field) < 2 || field[len(field)-1] != '"')
}

// splitKeyword returns the first token of line and everything after it,
// unsplit. line has already had comments stripped and been trimmed, so the
// first token is the directive keyword. A token ends at whitespace OR at an
// unspaced "(" - `require(` opens a block exactly as `require (` does, and
// splitting on whitespace alone would read "require(" as one unrecognized
// keyword and silently ignore the entire block.
func splitKeyword(line string) (keyword, rest string) {
	i := strings.IndexAny(line, " \t(")
	if i < 0 {
		return line, ""
	}
	if line[i] == '(' {
		return line[:i], line[i:]
	}
	return line[:i], line[i+1:]
}

// stripComment removes a trailing "//" comment, but only outside a quoted
// string: a module path may itself be a quoted string, and "//" inside one is
// not a comment.
func stripComment(line string) string {
	var out strings.Builder
	inString := false
	escaped := false
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if inString {
			out.WriteRune(c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out.WriteRune(c)
			continue
		}
		if c == '/' && i+1 < len(runes) && runes[i+1] == '/' {
			break
		}
		out.WriteRune(c)
	}
	return out.String()
}

// parseModulePath resolves one module-path field, honoring go.mod's quoted
// string form (e.g. `"github.com/a/b"`). A field that starts with `"` but
// does not end with one in the SAME field is not a bare token that happens to
// start with a quote - it is a quoted string this whitespace-based scan
// cannot see across, most likely one containing an internal space - and
// reporting it as a path with a stray leading quote would catalog unusable
// data as though it were real. ok is false in that case, and in the case of
// an invalid escape inside an otherwise well-formed quoted field.
func parseModulePath(field string) (path string, ok bool) {
	if field == "" {
		return "", false
	}
	if field[0] != '"' {
		return field, true
	}
	if len(field) < 2 || field[len(field)-1] != '"' {
		return "", false
	}
	u, err := strconv.Unquote(field)
	if err != nil {
		return "", false
	}
	return u, true
}
