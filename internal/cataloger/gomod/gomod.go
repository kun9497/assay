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
// asked for.
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
				// Not a version any comparer can place inside a range.
				// Counting it as cataloged would claim the module was
				// evaluated when it was not; dropping it silently would
				// remove it from the inventory without removing it from the
				// count of what was seen.
				stats.SkippedNoVersion++
				continue
			}
			name, version = rep.path, rep.version
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

// directives scans go.mod line by line and collects every require and
// replace directive. go.mod is line-oriented: require, replace, exclude and
// retract each have a single-line form and a `keyword ( ... )` block form, so
// blockKind tracks which directive - if any - the current line is inside.
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
			apply(blockKind, line, &requires, replaceAny, replaceExact)
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
			apply(keyword, rest, &requires, replaceAny, replaceExact)
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
	return requires, replaceAny, replaceExact, nil
}

// apply processes one directive body: either the remainder of a single-line
// directive, or one line inside a `keyword ( ... )` block. A block line
// carries no keyword of its own, so both forms share this parsing.
func apply(keyword, body string, requires *[]requirement, replaceAny, replaceExact map[string]replacement) {
	switch keyword {
	case "require":
		fields := strings.Fields(body)
		if len(fields) < 2 {
			return
		}
		*requires = append(*requires, requirement{path: unquote(fields[0]), version: fields[1]})

	case "replace":
		oldPath, oldVersion, rep, ok := parseReplace(body)
		if !ok {
			return
		}
		if oldVersion == "" {
			replaceAny[oldPath] = rep
		} else {
			replaceExact[oldPath+"@"+oldVersion] = rep
		}

	case "exclude", "retract":
		// Neither changes what is linked into a build: exclude removes one
		// version from consideration during resolution, retract is a
		// module author's advisory against its own past release. Nothing to
		// report from either.
	}
}

// parseReplace splits a replace directive body on "=>". The right-hand
// side's field count decides its shape: two fields is a module and a
// version, one field is a filesystem path with no version. oldVersion is
// empty when the left-hand side named no version (an unqualified replace).
func parseReplace(body string) (oldPath, oldVersion string, rep replacement, ok bool) {
	parts := strings.SplitN(body, "=>", 2)
	if len(parts) != 2 {
		return "", "", replacement{}, false
	}

	left := strings.Fields(parts[0])
	if len(left) == 0 {
		return "", "", replacement{}, false
	}
	oldPath = unquote(left[0])
	if len(left) >= 2 {
		oldVersion = left[1]
	}

	right := strings.Fields(parts[1])
	switch len(right) {
	case 1:
		rep = replacement{filesystem: true}
	case 2:
		rep = replacement{path: unquote(right[0]), version: right[1]}
	default:
		return "", "", replacement{}, false
	}
	return oldPath, oldVersion, rep, true
}

// splitKeyword returns the first whitespace-separated token of line and
// everything after it, unsplit. line has already had comments stripped and
// been trimmed, so the first token is the directive keyword.
func splitKeyword(line string) (keyword, rest string) {
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return line, ""
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

// unquote strips go.mod's quoted-string form for a module path, e.g.
// `"github.com/a/b"`. Most paths are bare; strconv.Unquote handles the rare
// quoted ones the same way the go.mod grammar does. A field that is not a
// valid quoted string (or is not quoted at all) is returned unchanged.
func unquote(field string) string {
	if len(field) >= 2 && field[0] == '"' && field[len(field)-1] == '"' {
		if u, err := strconv.Unquote(field); err == nil {
			return u
		}
	}
	return field
}
