package osv

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultUbuntuTrackerURL is Canonical's own CVE tracker, the source
// ubuntu_fixstate.go's lookup is built from (D85). git, not an archive
// download: there is no bulk export of this data in any other shape, and the
// repository itself is small enough (a git working tree of individually
// authored text files, not a database dump) that a shallow clone is the
// simplest thing that reads it at all.
const DefaultUbuntuTrackerURL = "https://git.launchpad.net/ubuntu-cve-tracker"

// lookGit resolves the git binary, exec.LookPath by default. A package var
// rather than a call inlined in ubuntuTrackerSync so a test can simulate a
// machine with no git installed without touching the process's real PATH --
// this is the "injectable runner seam" the brief asks for, chosen over a
// PATH-manipulation test because that would still invoke a real git binary
// if this machine's PATH search order does not behave the way the test
// assumes, on Windows especially (PATHEXT, App Execution Aliases).
var lookGit = exec.LookPath

// ubuntuTrackerMissingGit is returned when the git binary cannot be found.
// Named so main.go's provider-loop error wrapping ("error: provider osv:
// %v") reads as a complete sentence, and so UBUNTU_TRACKER_ENABLE=0 is
// always in the same breath as the failure -- this is D85's "never silently
// skip" rule: a build that produced a database with no Ubuntu fix-state
// data because git happened to be missing must fail loudly, the same
// discipline extrasDisclosure's own history exists to enforce (CLAUDE.md's
// "the extrasDisclosure lesson").
func ubuntuTrackerMissingGit(err error) error {
	return fmt.Errorf("git binary not found (%w); the Ubuntu CVE tracker cannot be fetched "+
		"without it -- install git, or set UBUNTU_TRACKER_ENABLE=0 to build without Ubuntu "+
		"fix-state data (findings will report FixState unknown instead of wont-fix/not-fixed)", err)
}

// gitRun runs one git subcommand. dir == "" runs with the process's own
// working directory (only `clone`'s destination does not exist yet, so it is
// the one caller that passes ""); every other call passes the spool
// directory. Output is captured either way so a failure's message carries
// git's own stderr rather than just an exit code.
func gitRun(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// ubuntuTrackerSync brings dir to the tracker's current HEAD and returns
// that HEAD's commit timestamp -- D12's DataAsOf, read from the data itself
// rather than the local clock, so a stale mirror or a clone that silently
// failed to advance cannot read as fresh.
//
// A fresh dir (no .git yet) is a shallow clone. A dir already synced by a
// previous build is `fetch --depth 1` + `reset --hard`, not a second clone:
// this is what makes a scheduled rebuild cheap after the first one, the same
// incremental shape D58's delta gives Red Hat's own CSAF sync. `origin HEAD`
// (not a hardcoded branch name) fetches whatever the remote's own default
// branch currently is, so a rename on Canonical's side does not silently
// stop advancing this clone.
func ubuntuTrackerSync(ctx context.Context, dir, url string) (time.Time, error) {
	if _, err := lookGit("git"); err != nil {
		return time.Time{}, ubuntuTrackerMissingGit(err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		if _, err := gitRun(ctx, dir, "fetch", "--depth", "1", "origin", "HEAD"); err != nil {
			return time.Time{}, fmt.Errorf("ubuntu tracker: %w", err)
		}
		if _, err := gitRun(ctx, dir, "reset", "--hard", "FETCH_HEAD"); err != nil {
			return time.Time{}, fmt.Errorf("ubuntu tracker: %w", err)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return time.Time{}, fmt.Errorf("ubuntu tracker: create spool root: %w", err)
		}
		if _, err := gitRun(ctx, "", "clone", "--depth", "1", url, dir); err != nil {
			return time.Time{}, fmt.Errorf("ubuntu tracker: %w", err)
		}
	}

	out, err := gitRun(ctx, dir, "log", "-1", "--format=%cI")
	if err != nil {
		return time.Time{}, fmt.Errorf("ubuntu tracker: read HEAD timestamp: %w", err)
	}
	asOf, err := time.Parse(time.RFC3339, strings.TrimSpace(string(out)))
	if err != nil {
		return time.Time{}, fmt.Errorf("ubuntu tracker: parse HEAD timestamp %q: %w", out, err)
	}
	return asOf, nil
}

// ubuntuSpool is the directory ubuntuTrackerSync clones/syncs into: a FIXED
// name under os.TempDir(), the same root redhat.spool and suse.spool use
// (os.CreateTemp("", pattern) resolves against os.TempDir() too -- see
// spool.go in both packages). It is deliberately NOT a randomized
// os.CreateTemp-style name the way those are: those two spool one ephemeral
// archive per build and remove it once parsed, while this spools a git
// working tree that a SECOND build must find again to fetch+reset rather
// than reclone -- randomizing the name would make every build a fresh
// clone, which is exactly the cost this shape exists to avoid.
func (p *Provider) ubuntuSpool() string {
	if p.ubuntuSpoolDir != "" {
		return p.ubuntuSpoolDir
	}
	return filepath.Join(os.TempDir(), "assay-ubuntu-cve-tracker")
}

func (p *Provider) ubuntuURL() string {
	if p.ubuntuTrackerURL != "" {
		return p.ubuntuTrackerURL
	}
	return DefaultUbuntuTrackerURL
}

// WithUbuntuTracker gates D85's fix-state stamping and returns p for
// chaining, the same shape WithProgress uses.
//
// Defaults to false from New() -- deliberately the opposite of production's
// default. REDHAT_ENABLE and its siblings gate whether main.go constructs an
// entire *provider*; this gates a sub-feature of a provider dozens of
// existing tests already construct directly, including ones that fetch an
// "Ubuntu" archive with no git repository anywhere nearby
// (TestFetch_DebianUbuntuRockyAndAlmaZeroRecordsIsAnError). Defaulting this
// on inside New() would make every one of those attempt a real git clone.
// main.go's dbUpdateProviders is what makes it on by default in production
// (UBUNTU_TRACKER_ENABLE, default true -- D51's precedent: the published
// artifact carries what defaults ship) via this same opt-in-at-the-call-site
// shape WithProgress already uses for its own safe zero value.
func (p *Provider) WithUbuntuTracker(enabled bool) *Provider {
	p.ubuntuTrackerEnabled = enabled
	return p
}

// UbuntuTrackerEnabled reports whether D85's tracker is on. It exists for
// cross-package tests (cmd/assay's dbUpdateProviders wiring test) to observe
// that UBUNTU_TRACKER_ENABLE actually reached WithUbuntuTracker, the same
// "prove the option reached construction" property newRedHatProvider and its
// siblings get from being swappable spies -- WithUbuntuTracker mutates the
// concrete *osv.Provider in place instead of being swapped at construction,
// so there is no spy to inspect, and this getter is the least-machinery way
// to look at what it left behind.
func (p *Provider) UbuntuTrackerEnabled() bool { return p.ubuntuTrackerEnabled }

// ubuntuTrackerDisabledDisclosure is printed once, in place of the sync +
// parse lines, whenever Ubuntu is being fetched but UBUNTU_TRACKER_ENABLE is
// off. The extrasDisclosure register (amazon.go's own doc comment): a build
// that silently narrows what it stamps looks exactly like one that is
// broken, so the gap is named on stderr rather than left to a comment nobody
// reads.
const ubuntuTrackerDisabledDisclosure = "osv: UBUNTU_TRACKER_ENABLE=0 -- Ubuntu findings with no " +
	"fixed version will report FixState unknown rather than wont-fix/not-fixed; Canonical's own " +
	"CVE tracker was not consulted"

// loadUbuntuTracker syncs the spool (ubuntuTrackerSync) and parses it
// (parseUbuntuTracker), printing one progress line for each step -- the
// clone/sync size and HEAD timestamp first, since that is known before
// parsing starts, then the tuple/skip counts once parsing finishes. Two
// lines rather than one because the first is worth seeing even if the
// second takes a while: active/ and retired/ together hold tens of
// thousands of files.
func (p *Provider) loadUbuntuTracker(ctx context.Context, st *stats) (*ubuntuTracker, error) {
	dir := p.ubuntuSpool()
	url := p.ubuntuURL()
	asOf, err := ubuntuTrackerSync(ctx, dir, url)
	if err != nil {
		return nil, err
	}
	size := dirSize(dir)
	fmt.Fprintf(p.progress, "ubuntu tracker (D85): synced %s into %s (%s on disk), HEAD data as of %s\n",
		url, dir, humanBytes(size), asOf.Format(time.RFC3339))

	tracker, err := parseUbuntuTracker(dir, st)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(p.progress, "ubuntu tracker (D85): %d tuple(s) loaded, %d unknown-codename line(s) "+
		"skipped, %d file(s) unparsed\n", st.UbuntuTuplesLoaded, st.UbuntuUnknownCodename, st.UbuntuFilesUnparsed)
	return tracker, nil
}

// dirSize sums regular file sizes under dir, best-effort: an error partway
// through (a file removed mid-walk by a concurrent process, vanishingly
// unlikely for a spool this build owns exclusively) yields whatever was
// summed so far rather than failing the build over a diagnostic number.
func dirSize(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// humanBytes renders a byte count as a fixed-point MB figure. Nothing this
// build reports is small enough for a KB/GB scale to matter -- the tracker's
// working tree is tens of MB, and a wrong-order-of-magnitude bug (MB read as
// GB) would be far more misleading than the modest precision loss below KB.
func humanBytes(n int64) string {
	return fmt.Sprintf("%.1f MB", float64(n)/1e6)
}
