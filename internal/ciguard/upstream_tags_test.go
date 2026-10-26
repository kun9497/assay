// Package ciguard holds tests about the repository's CI configuration rather
// than about any one package's code.
//
// The 2026-10-22 audit (gap 5) found internal/provider/suse's live-feed test
// behind the upstreamvectors tag with no CI step running it: counted as
// coverage, never executed -- the exact shape ci.yml's own comment on the
// version vectors warns about. Nothing tied "a package has tagged tests" to "a
// workflow runs that package with the tag", so the gap opened silently when
// the SUSE provider landed and stayed open for two months.
package ciguard

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const repoRoot = "../.."

// taggedPackages returns every package directory (slash-separated, relative to
// the repository root, "./"-prefixed and "/"-suffixed the way ci.yml spells
// them) holding a test file whose build constraint names tag.
func taggedPackages(t *testing.T, tag string) []string {
	t.Helper()
	seen := map[string]bool{}
	constraint := regexp.MustCompile(`^//go:build\s+(.*)$`)
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if m := constraint.FindStringSubmatch(line); m != nil {
				for _, w := range regexp.MustCompile(`[A-Za-z0-9_.]+`).FindAllString(m[1], -1) {
					if w == tag {
						rel, _ := filepath.Rel(repoRoot, filepath.Dir(path))
						seen["./"+filepath.ToSlash(rel)+"/"] = true
					}
				}
				break
			}
			if line != "" && !strings.HasPrefix(line, "//") {
				break // past the header: no build constraint in this file
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// taggedRuns returns, for every `go test` command line in the workflow files
// that passes -tags naming tag, the package arguments it names, and fails the
// test outright on a -run filter: the version-vector step once ran with
// `-run <one test>` and silently excluded every replay added after it.
func taggedRuns(t *testing.T, tag string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(repoRoot, ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflow files found (err=%v)", err)
	}
	covered := map[string]bool{}
	for _, wf := range files {
		b, err := os.ReadFile(wf)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			i := indexOf(fields, "go")
			if i < 0 || i+1 >= len(fields) || fields[i+1] != "test" {
				continue
			}
			args := fields[i+2:]
			if !hasTag(args, tag) {
				continue
			}
			for j, a := range args {
				if a == "-run" || strings.HasPrefix(a, "-run=") {
					t.Errorf("%s: %q filters a tagged run with -run; a test added later would never execute", filepath.Base(wf), strings.TrimSpace(line))
				}
				if strings.HasPrefix(a, "./") && (j == 0 || args[j-1] != "-tags") {
					p := a
					if !strings.HasSuffix(p, "/") && !strings.HasSuffix(p, "...") {
						p += "/"
					}
					covered[p] = true
				}
			}
		}
	}
	return covered
}

func indexOf(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

func hasTag(args []string, tag string) bool {
	for i, a := range args {
		var list string
		switch {
		case a == "-tags" && i+1 < len(args):
			list = args[i+1]
		case strings.HasPrefix(a, "-tags="):
			list = strings.TrimPrefix(a, "-tags=")
		default:
			continue
		}
		for _, w := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' }) {
			if w == tag {
				return true
			}
		}
	}
	return false
}

func coveredBy(pkg string, covered map[string]bool) bool {
	if covered[pkg] {
		return true
	}
	for c := range covered {
		if strings.HasSuffix(c, "/...") && strings.HasPrefix(pkg, strings.TrimSuffix(c, "...")) {
			return true
		}
	}
	return false
}

func TestEveryUpstreamVectorsPackageRunsInCI(t *testing.T) {
	pkgs := taggedPackages(t, "upstreamvectors")
	if len(pkgs) == 0 {
		t.Fatal("found no upstreamvectors-tagged test files; the walk is broken, not the repository")
	}
	covered := taggedRuns(t, "upstreamvectors")
	for _, p := range pkgs {
		if !coveredBy(p, covered) {
			t.Errorf("%s has upstreamvectors-tagged tests but no workflow runs `go test -tags upstreamvectors %s`", p, p)
		}
	}
}
