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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

const repoRoot = "../.."

// taggedPackages returns every package directory (slash-separated, relative to
// the repository root, "./"-prefixed and "/"-suffixed the way ci.yml spells
// them) holding a test file whose build constraint names tag.
func taggedPackages(root, tag string) ([]string, error) {
	seen := map[string]bool{}
	constraint := regexp.MustCompile(`^//go:build\s+(.*)$`)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
						rel, _ := filepath.Rel(root, filepath.Dir(path))
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
	var out []string
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, err
}

// taggedRuns returns, for every `go test` command line in root's workflow
// files that passes -tags naming tag, the package arguments it names, and
// separately every such line filtered by -run: the version-vector step once
// ran with `-run <one test>` and silently excluded every replay added after it.
func taggedRuns(root, tag string) (covered map[string]bool, filtered []string, err error) {
	files, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		return nil, nil, err
	}
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("no workflow files under %s", root)
	}
	covered = map[string]bool{}
	for _, wf := range files {
		b, err := os.ReadFile(wf)
		if err != nil {
			return nil, nil, err
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
					filtered = append(filtered, filepath.Base(wf)+": "+strings.TrimSpace(line))
				}
				if strings.HasPrefix(a, "./") && (j == 0 || args[j-1] != "-tags") {
					p := a
					if !strings.HasSuffix(p, "/") {
						p += "/"
					}
					covered[p] = true
				}
			}
		}
	}
	return covered, filtered, nil
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

// coveredBy matches a package to a tagged run's argument exactly. A `./...`
// pattern is deliberately not understood: every tagged step names its
// package, and a pattern would only make the guard report a covered package
// as missing -- loud, not silent.
func coveredBy(pkg string, covered map[string]bool) bool {
	return covered[pkg]
}

// problems is the whole check over one repository root: every tagged package
// no workflow runs with the tag, then every tagged run narrowed by -run.
func problems(root, tag string) ([]string, error) {
	pkgs, err := taggedPackages(root, tag)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("found no %s-tagged test files under %s; the walk is broken, not the repository", tag, root)
	}
	covered, filtered, err := taggedRuns(root, tag)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range pkgs {
		if !coveredBy(p, covered) {
			out = append(out, p+" has "+tag+"-tagged tests but no workflow runs `go test -tags "+tag+" "+p+"`")
		}
	}
	for _, l := range filtered {
		out = append(out, l+" filters a tagged run with -run; a test added later would never execute")
	}
	return out, nil
}

func TestEveryUpstreamVectorsPackageRunsInCI(t *testing.T) {
	got, err := problems(repoRoot, "upstreamvectors")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		t.Error(p)
	}
}

// The check against a repository it must reject. Without this the guard is
// held only by the real ci.yml happening to be right: break problems() so it
// reports nothing and the test above stays green.
func TestGuardRejectsAMissingStepAndARunFilter(t *testing.T) {
	got, err := problems(filepath.Join("testdata", "repo"), "upstreamvectors")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"./pkg/missing/ has upstreamvectors-tagged tests but no workflow runs `go test -tags upstreamvectors ./pkg/missing/`",
		"ci.yml: - run: go test -tags upstreamvectors ./pkg/filtered/ -run TestOne filters a tagged run with -run; a test added later would never execute",
	}
	if !slices.Equal(got, want) {
		t.Errorf("problems = %q\nwant       %q", got, want)
	}
}
