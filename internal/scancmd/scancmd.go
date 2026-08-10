// Package scancmd implements `assay scan`.
package scancmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/apkdb"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/dirscan"
	"github.com/kun9497/assay/internal/cataloger/dpkgdb"
	"github.com/kun9497/assay/internal/cataloger/gobinary"
	"github.com/kun9497/assay/internal/cataloger/osrelease"
	"github.com/kun9497/assay/internal/cataloger/rpmdb"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/source"
	"github.com/kun9497/assay/internal/store"
)

// Options are the --fail-on* gates that turn a completed, trustworthy scan's
// results into an exit code (D21). They are entirely separate from whether
// the scan could run at all: Run's existing exit-2 paths — a target that
// could not be opened, a missing or incomplete database, a store error, and
// the unconditional !sum.Trustworthy() check (D11) — all fire before Options
// is even consulted. Options{}, the zero value produced when no flag is
// given, must reproduce today's behaviour exactly: a completed, trustworthy
// scan exits 0 no matter what it found.
type Options struct {
	// FailOn is the --fail-on threshold, or nil if the flag was not given.
	// A pointer, not a bare severity.Band, because severity.None is a real,
	// requestable threshold (and Band's zero value), so it cannot also mean
	// "not set" without being ambiguous with an explicit `--fail-on none`.
	//
	// A finding trips this via Finding.Severity.AtOrAbove(*FailOn) alone.
	// There is deliberately no extra "unless the finding is unknown" check
	// here: AtOrAbove already guarantees severity.Unknown never satisfies any
	// threshold, including None (D17) — a second check reaching the same
	// answer would just be a second place for it to drift from AtOrAbove.
	FailOn *severity.Band
	// FailOnUnknown makes a finding with an unrated severity (severity.Unknown)
	// trip the scan on its own, exit 1. It has to be a separate flag rather
	// than folded into FailOn precisely because AtOrAbove refuses to let
	// Unknown satisfy any threshold — this is the deliberate, opt-in way to
	// ask for that anyway.
	FailOnUnknown bool
	// FailOnIncomplete makes the scan exit 2 when any package's evaluation
	// was not complete: either a whole package the cataloger or matcher never
	// reached (report.Summary.NotEvaluated), or one advisory check on an
	// otherwise-evaluated package that could not be judged
	// (report.Summary.IncompleteChecks). Both mean the same thing to a
	// caller — there could be a finding this run did not see — which is why
	// this exits 2 rather than 1, and why it outranks FailOn/FailOnUnknown
	// under D11's 2 > 1 > 0 precedence.
	FailOnIncomplete bool
	// FailOnIncompleteTarget narrows FailOnIncomplete to what the person
	// running the scan can act on (D36): an installed version that will not
	// parse, not an advisory whose bound will not.
	//
	// It exists because the broad gate is unusable in a pipeline that meets any
	// of the 85 malformed range bounds still in the database. Those are upstream
	// data nobody scanning can fix, so a job gated on them is red on every run
	// until somebody turns the gate off — and a gate that gets turned off
	// protects nothing. Both flags are honoured together; the broad one is
	// unchanged, because exit codes are contract (D11) and quietly narrowing an
	// existing flag would break pipelines that rely on it.
	FailOnIncompleteTarget bool
	// FailOnUnfixable makes a finding no source can offer a fix for trip the
	// scan on its own, exit 1 (D48).
	//
	// A separate flag rather than folding these into FailOn, and the reasoning
	// is D17's exactly: an unfixable finding has a real band, so unlike
	// severity.Unknown it ALREADY trips --fail-on when it is severe enough.
	// This flag is for the opposite ask -- fail on them whatever the band --
	// which is a different question and cannot be spelled as a threshold.
	//
	// Why it is not the default: Red Hat's feed alone contributes 4,491
	// unfixable findings for the kernel on RHEL 9, against single or low
	// double digits for every other base package. A host scan gated on these
	// is red on every run with nothing anyone can do about it, and D36 already
	// records what happens to such a gate -- somebody turns it off, and a gate
	// that is off protects nothing.
	FailOnUnfixable bool
	// FailOnUnfixableWontFix narrows FailOnUnfixable to the findings a
	// vendor has declared it will never fix (D52), the way
	// FailOnIncompleteTarget narrows FailOnIncomplete (D36) — and for the
	// same reason the paragraph above gives. The broad gate is red on every
	// run of a RHEL host scan and gets switched off; this one fires on the
	// subset where waiting is not a strategy, which on the images measured is
	// 11 of 416 unfixable findings on ubi9 and 59 of 505 on ubi8.
	//
	// Independent of FailOnUnfixable rather than a mode of it: passing both
	// is redundant but not contradictory, and the broad one subsumes this.
	FailOnUnfixableWontFix bool
	// Output selects the renderer: "" and "table" both mean the human table
	// (Options{}'s zero value must reproduce today's behaviour exactly, the
	// same rule Options.FailOn* already follows), "json" means the stable
	// document report.JSON writes (D18: the flag name follows grype's own
	// --output). The CLI layer (cmd/assay) rejects any other value before
	// Run ever sees it — an invalid value here would be a silently wrong
	// renderer choice, not a silently-ignored flag, but the earlier a typo
	// surfaces the better.
	Output string
	// Explain, when non-empty, selects one advisory to explain instead of
	// rendering the table or JSON: its own ID, or any alias/upstream
	// identifier it carries (D3) — whatever a reader would have grepped the
	// table's ALIASES column for. This is D10 made visible: which range
	// matched, which comparer decided it, and which name reached the
	// advisory (D8), the exact fields Evidence and MatchedName exist to
	// carry. It does not change the --fail-on* verdict below: explain mode
	// picks the renderer, not the exit code.
	Explain string
}

// The two files an image cataloger reads, named as they appear as tar entries
// (no leading slash) — which is also the form Image.Files normalises its own
// keys to, so a lookup with a leading slash would just miss.
const (
	osReleasePath = "etc/os-release"
	apkDBPath     = "lib/apk/db/installed"
	// dpkgDBPath is the ordinary Debian and Ubuntu database. Distroless images
	// use /var/lib/dpkg/status.d as a DIRECTORY of one stanza per package
	// instead, which Files cannot ask for — it takes exact paths. Those images
	// therefore reach the "no supported package database" error below, which
	// names them, rather than being reported as having no packages. Never
	// glob status*: debian:* ships status-old holding a full duplicate of
	// every stanza, and matching it would double the inventory.
	dpkgDBPath = "var/lib/dpkg/status"
)

// rpmDBDirs are the two places an RPM database lives, newest convention first.
//
// BOTH are probed, and that is not belt and braces. `/var/lib/rpm` is a
// SYMLINK on RHEL 10, CentOS Stream 10, Fedora 36+ and every openSUSE — the
// real directory moved to /usr/lib/sysimage/rpm with Fedora's RelocateRPMToUsr
// — and Image.Files matches exact tar entry names. It follows a symlink that IS
// the wanted path; it does not follow one on a DIRECTORY COMPONENT of it, which
// is the same limitation that makes distroless status.d a named error (D42).
// So a reader that probed only the traditional path would find nothing in those
// images' layers and, without D43's hard error below, would report a 172-package
// image as having none.
var rpmDBDirs = []string{"usr/lib/sysimage/rpm", "var/lib/rpm"}

// rpmDBFiles are the file names inside those directories, one per backend.
// Packages is BerkeleyDB (RHEL 8 and older, Amazon Linux 2) and rpmdb.sqlite is
// SQLite (RHEL 9 and newer); both are read. Packages.db is ndb, which only
// openSUSE and SLES use — it is probed anyway, because finding one and naming
// it is a refusal somebody can act on where finding nothing is
// indistinguishable from a clean image.
var rpmDBFiles = []string{"rpmdb.sqlite", "rpmdb.sqlite-wal", "Packages", "Packages.db"}

// rpmFamilies are the /etc/os-release IDs whose package database is an rpmdb.
//
// Routing on ID rather than on the `elN` release string is deliberate: ubi
// reports rhel, almalinux reports almalinux and rocky reports rocky, and the
// three write their module builds differently enough that matching one distro's
// advisory versions against another's is a real hazard (see the RHEL entry in
// docs/deferred-decisions.md). The list is used only to turn "no database
// found" into a specific error, so an ID missing from it costs a vaguer message
// and nothing else.
var rpmFamilies = map[string]bool{
	"rhel": true, "centos": true, "fedora": true, "almalinux": true,
	"rocky": true, "ol": true, "amzn": true, "openEuler": true,
	"sles": true, "opensuse-leap": true, "opensuse-tumbleweed": true,
	"azurelinux": true, "mariner": true,
}

// rpmDBPaths is every tar entry the RPM probe asks for.
func rpmDBPaths() []string {
	out := make([]string, 0, len(rpmDBDirs)*len(rpmDBFiles))
	for _, d := range rpmDBDirs {
		for _, f := range rpmDBFiles {
			out = append(out, d+"/"+f)
		}
	}
	return out
}

// foundRPMDB is the RPM database an image carries. Exactly one of the three
// paths is set.
type foundRPMDB struct {
	sqlitePath string
	// walSize is the size of the sibling -wal file, or rpmdb.WALAbsent when the
	// image has no such entry at all. Carried explicitly because ReadSQLite
	// refuses to guess (D45), and "Files did not return it" is a real answer
	// here: Files walks every layer, so absence means the image does not have
	// it rather than that nobody looked.
	walSize int64
	bdbPath string // BerkeleyDB: RHEL 8 and older, Amazon Linux 2
	ndbPath string // ndb: openSUSE and SLES only
}

// findRPMDB picks the database out of the probed files, preferring the SQLite
// backend and then the relocated directory.
func findRPMDB(files map[string]source.FileFromLayer) (foundRPMDB, bool) {
	for _, d := range rpmDBDirs {
		p := d + "/rpmdb.sqlite"
		if files[p].Data == nil {
			continue
		}
		db := foundRPMDB{sqlitePath: p, walSize: rpmdb.WALAbsent}
		if w, ok := files[p+"-wal"]; ok && w.Data != nil {
			db.walSize = int64(len(w.Data))
		}
		return db, true
	}
	for _, d := range rpmDBDirs {
		if files[d+"/Packages"].Data != nil {
			return foundRPMDB{bdbPath: d + "/Packages"}, true
		}
		if files[d+"/Packages.db"].Data != nil {
			return foundRPMDB{ndbPath: d + "/Packages.db"}, true
		}
	}
	return foundRPMDB{}, false
}

// Run scans whatever one target argument names — an SBOM, a container image
// (a registry reference, a docker-archive: tarball, or an oci-dir: layout), a
// Go binary, or a directory with a go.mod — chosen by source.Classify so one
// argument reaches the right loader (D22). Once the
// scan completes and the result is judged trustworthy (D11), opts decides
// the exit code; Options{} reproduces the pre-slice-4 behaviour of always
// exiting 0 on a trustworthy scan, findings or not.
func Run(ctx context.Context, dbPath, target string, opts Options, stdout, stderr io.Writer) int {
	var (
		inventory pkgmeta.Target
		cat       cyclonedx.Stats
		// manifests stays zero for every target that is not a directory, and
		// its disclosure loop below is guarded on kind, so an image or SBOM
		// scan cannot start printing directory diagnostics.
		manifests dirscan.Manifests
	)

	kind, path, err := source.Classify(target)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	// D22: the classifier's decision is reported IMMEDIATELY — before the
	// cataloger below ever runs, not after it succeeds — so a wrong guess is
	// visible in the scan's own output even when the cataloger then fails.
	// Printing this after the switch instead meant every error path returned
	// 2 before it was ever reached: a typo'd path that fell through to the
	// registry loader reported "dial tcp: lookup .: no such host" with no
	// hint that assay had read it as an image reference at all, and a
	// directory with no go.mod reported "read go.mod: ... no such file"
	// with no hint it had been read as a directory — exactly the
	// "confusing downstream error" TargetKind's own doc comment
	// (internal/source/image.go) says Classify exists to prevent. stderr,
	// never stdout, so `--output json | jq` stays clean.
	fmt.Fprintf(stderr, "scanned %s as %s %s\n", target, article(kind), kind)

	// path has any file:/dir:/sbom: prefix stripped (source.Classify's own
	// contract); target does not. The three filesystem catalogers below must
	// get path — handing gobinary.Parse or gomod.Parse the raw target would
	// make "dir:./x" the directory name itself. catalogImage is the one
	// exception: it re-parses target itself (docker-archive:/oci-dir: are
	// image-loader syntax, not a stripped prefix), so it keeps getting target.
	switch kind {
	case source.TargetImage:
		t, stats, err := catalogImage(ctx, target)
		if err != nil {
			// No "open %s:" wrapper. Every error reaching here already names
			// the target, and the one that matters most is not an open failure
			// at all — "no supported package database found" comes from an
			// image that opened perfectly well, and saying "open" first sends
			// the reader looking for the wrong problem.
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		inventory, cat = t, stats

	case source.TargetGoBinary:
		t, stats, err := gobinary.Parse(path)
		if err != nil {
			// gobinary.Parse's own error already names path (buildinfo's own
			// message does), so no extra wrapper here either.
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		inventory, cat = t, stats

	case source.TargetDirectory:
		t, stats, mf, err := dirscan.Parse(path)
		if err != nil {
			// dirscan.Parse's own error names the root, and the only error it
			// returns is "nothing here this scan understands". An individual
			// manifest that could not be read is reported below instead, so
			// one bad lockfile never costs the rest of the tree.
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		inventory, cat, manifests = t, stats, mf

	default: // source.TargetSBOM
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(stderr, "error: open %s: %v\n", path, err)
			return 2
		}
		defer f.Close()

		t, stats, err := cyclonedx.Parse(f)
		if err != nil {
			fmt.Fprintf(stderr, "error: parse %s: %v\n", path, err)
			return 2
		}
		inventory, cat = t, stats
	}

	if kind == source.TargetDirectory {
		// D23: go.mod names what the module REQUIRES, not what a build
		// actually links — no toolchain is invoked, so replace/exclude/retract
		// resolution against the wider build graph never happens. Stated on
		// every SUCCESSFUL directory scan, not just when packages are
		// dropped, so the gap cannot be mistaken for a clean, complete result
		// (D20/D21's silent-partial-coverage failure, arriving through a new
		// door).
		//
		// Printed only when a go.mod was actually read, and with THAT
		// manifest's own count rather than cat.Components. Since D26 a
		// directory scan merges several manifests, so the total belongs to all
		// of them — a caveat about go.mod carrying the whole tree's number
		// would be precisely wrong, which is worse than absent because it
		// reads as precise.
		if gomod, ok := manifests.GoMod(); ok {
			fmt.Fprintf(stderr, "go.mod names %d module(s); this is what was requested, "+
				"not what a build links - scan the built binary for that\n", gomod.Components)
		}
		// D26: every manifest the walk recognized and did not turn into
		// packages, named, with the reason. A count alone would tell a reader
		// something is missing without telling them what to do about it.
		//
		// These are exactly the trees the summary's "not evaluated" figure
		// CANNOT account for: a manifest that was never read produces no
		// package, so there is nothing for the skip counter to count. Before
		// this line existed, a directory holding go.mod beside
		// package-lock.json reported the Go packages, said "0 not evaluated",
		// and exited 0 while 24 findings went unmentioned.
		// D38: a line a manifest WAS read but could not use. Named rather than
		// only counted — "3 package(s) with no version to compare" does not say
		// which three, and pinning them is the action being asked for. Printed
		// as its own list so it is not read as a claim that the file went
		// unread, which is the opposite of what happened.
		for _, u := range manifests.Unusable {
			fmt.Fprintf(stderr, "not pinned: %s: %s (%s)\n", u.Path, u.Line, u.Reason)
		}
		for _, u := range manifests.Unread {
			fmt.Fprintf(stderr, "not read: %s (%s)\n", u.Path, u.Reason)
		}
	}

	db, err := store.Open(dbPath)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSchemaMismatch) ||
			errors.Is(err, store.ErrIncomplete) {
			fmt.Fprintf(stderr, "error: %v\n", err)
			fmt.Fprintln(stderr, "run `assay db update` to download it, or `assay db build` to build it from source")
			return 2
		}
		fmt.Fprintf(stderr, "error: open database: %v\n", err)
		return 2
	}
	defer db.Close()

	res, err := matcher.New(db).Match(inventory)
	if err != nil {
		fmt.Fprintf(stderr, "error: match: %v\n", err)
		return 2
	}

	// Three renderers, exactly one chosen: --explain replaces the report
	// with one advisory's evidence, --output json replaces it with the
	// stable document, and the default remains the human table. None of the
	// three changes what happens below — sum still decides Trustworthy() and
	// verdict() the same way regardless of which renderer produced it,
	// because explain/json pick a RENDERER, not a different notion of
	// what the scan found (D11's precedence is a property of the scan, not
	// of how it is displayed).
	var sum report.Summary
	switch {
	case opts.Explain != "":
		// Summarize, not Table: Table would also print to stdout, and
		// --explain must be the ONLY thing written there, the same
		// discipline --output json owes `| jq`.
		sum = report.Summarize(res, cat)
		n, werr := report.Explain(stdout, res, opts.Explain)
		if werr != nil {
			fmt.Fprintf(stderr, "error: write report: %v\n", werr)
			return 2
		}
		if n == 0 {
			// A typo'd or unmatched identifier is a request that could not
			// be honoured, not a vacuously successful empty report — the
			// same "loud, not silent" rule every other CLI input mistake in
			// this package already follows.
			fmt.Fprintf(stderr, "error: no finding matches advisory or alias %q\n", opts.Explain)
			return 2
		}
		// Explain is the one renderer that shows a single finding, so on its
		// own it discloses nothing about the rest of the scan. The table
		// prints the counts and the "Not evaluated" block; the JSON document
		// carries them in `summary`. Without this, `--explain X` on a target
		// where a third of the packages were never checked printed a
		// confident explanation, exited 0, and said so nowhere — a partial
		// scan folded silently into a clean verdict, which is the one thing
		// this project's CLI contract forbids outright.
		//
		// stderr, not stdout: stdout belongs to the explanation alone.
		if sum.NotEvaluated > 0 || sum.IncompleteChecks > 0 {
			fmt.Fprintf(stderr,
				"warning: %d package(s) not evaluated and %d check(s) incomplete - this scan is NOT complete\n",
				sum.NotEvaluated, sum.IncompleteChecks)
		}
	case opts.Output == "json":
		sum, err = report.JSON(stdout, res, cat)
		if err != nil {
			fmt.Fprintf(stderr, "error: write report: %v\n", err)
			return 2
		}
	default:
		sum, err = report.Table(stdout, res, cat)
		if err != nil {
			fmt.Fprintf(stderr, "error: write report: %v\n", err)
			return 2
		}
	}
	// D47's debt, paid on stderr so `--output json | jq` stays clean.
	//
	// Red Hat findings are matched against MAINLINE errata, because the
	// support channel that would pick between mainline, EUS, AUS, TUS and E4S
	// is a subscription attribute with no filesystem representation —
	// /etc/os-release says "9.8" and nothing on disk says which channel the
	// host is entitled to. Restricting to mainline is what makes the key
	// derivable at all, and it drops fixed-version ambiguity from 25.1% of
	// (CVE, package, major) groups to 6.1%; the residual is a real divergence
	// and a reader has to be told, not left to discover that a fixed version
	// they cannot install was quoted at them.
	//
	// Printed whenever a Red Hat finding was emitted rather than whenever the
	// distro is RHEL: a scan that produced none has nothing to caveat, and a
	// caveat attached to nothing is one readers learn to skip.
	if redHatFindings(res.Findings) {
		fmt.Fprintln(stderr,
			"note: Red Hat findings are matched against mainline RHEL errata. A host on "+
				"Extended Update Support, AUS, TUS or E4S may have a different fixed version "+
				"for the same CVE; the support channel is a subscription attribute and is not "+
				"readable from the filesystem.")
	}
	// The report already said so in prose; exiting 0 anyway would let CI read a
	// scan that evaluated nothing as a pass (D11).
	if !sum.Trustworthy() {
		fmt.Fprintf(stderr,
			"error: none of the %d component(s) could be evaluated; this result cannot be trusted\n",
			sum.Components)
		return 2
	}
	// A manifest that was found and could not be read is a statement about
	// coverage, and it has to reach the exit code the way every other
	// incomplete-coverage path does (D11: 2 outranks the content of the
	// result). Trustworthy() cannot see it — an unreadable manifest yields no
	// packages, so it contributes nothing to Components and nothing to the
	// skip counters, which is the same blind spot D26 exists to close, one
	// level up.
	//
	// Two cases, deliberately different. Nothing readable at all means the
	// scan could not run: that is an unconditional 2, and it restores what
	// happened before this cataloger existed, when gomod.Parse's error
	// returned 2 for a directory whose go.mod would not parse. A partial
	// failure is a normal incomplete scan, so it is opt-in through
	// --fail-on-incomplete rather than failing every CI job that has one bad
	// lockfile in a large tree (D21's reasoning for that flag being opt-in).
	if manifests.AnyFailed() {
		if len(manifests.Read) == 0 {
			fmt.Fprintln(stderr,
				"error: no manifest in this directory could be read; this result cannot be trusted")
			return 2
		}
		if opts.FailOnIncomplete {
			fmt.Fprintln(stderr,
				"error: at least one manifest could not be read (--fail-on-incomplete)")
			return 2
		}
	}
	return verdict(opts, sum, res.Findings)
}

// article returns the indefinite article to pair with kind.String() so the
// disclosure line reads as English rather than always defaulting to "a" —
// "a sbom" and "a image" are the two spellings that read wrong (an SBOM is
// pronounced as its own letters; "image" starts on a vowel sound).
// "directory" and "go-binary" both take "a".
func article(kind source.TargetKind) string {
	switch kind {
	case source.TargetImage, source.TargetSBOM:
		return "an"
	default:
		return "a"
	}
}

// verdict turns a completed, trustworthy scan into an exit code under the
// three --fail-on* gates and D11's 2 > 1 > 0 precedence: an untrustworthy —
// here, incomplete — result outranks its content, so FailOnIncomplete is
// checked first and, if it fires, the findings below are never even
// consulted. Options{} (no flags at all) always returns 0, which is what
// keeps a scan with no flags set exiting exactly as it did before this gate
// existed.
//
// FailOnUnknown reads sum.UnknownSeverity rather than re-deriving "is there
// an unrated finding" by looping findings itself: report.Table already
// counts exactly that, and its own doc comment says a --fail-on-unknown gate
// is meant to read it directly. Re-deriving the same fact a second way here
// would be the identical two-paths-can-drift hazard the brief calls out for
// AtOrAbove, one field over — so the loop below exists only for FailOn.
func verdict(opts Options, sum report.Summary, findings []matcher.Finding) int {
	if opts.FailOnIncomplete && (sum.NotEvaluated > 0 || sum.IncompleteChecks > 0) {
		return 2
	}
	// D36: the same exit code for a narrower cause. Deliberately a second
	// condition rather than a mode on the first — the two are independent
	// questions ("did anything go unchecked" and "did MY data go unchecked"),
	// and a pipeline may reasonably ask both.
	if opts.FailOnIncompleteTarget && sum.TargetIncomplete > 0 {
		return 2
	}
	if opts.FailOnUnknown && sum.UnknownSeverity > 0 {
		return 1
	}
	// D48. Checked beside FailOnUnknown rather than inside the loop below,
	// because Summarize already counted it and re-deriving the same fact a
	// second way here is the drift hazard the FailOnUnknown comment names one
	// field over.
	if opts.FailOnUnfixable && sum.Unfixable > 0 {
		return 1
	}
	// D52, and reading Summarize's count for the same reason: the renderer,
	// the JSON and this gate must not each decide separately what counts as
	// will-not-fix.
	if opts.FailOnUnfixableWontFix && sum.WontFix > 0 {
		return 1
	}
	for _, f := range findings {
		// No separate "unless f.Severity is Unknown" guard: AtOrAbove already
		// returns false whenever the finding's band is Unknown, against any
		// threshold including None (D17). See the Options.FailOn doc comment.
		if opts.FailOn != nil && f.Severity.AtOrAbove(*opts.FailOn) {
			return 1
		}
	}
	return 0
}

// catalogImage opens ref and builds a Target from it. It is a thin wrapper
// around catalogFromImage so tests can drive the cataloging logic directly,
// against a hand-built *source.Image, without going through a real registry,
// tarball, or layout.
func catalogImage(ctx context.Context, ref string) (pkgmeta.Target, cyclonedx.Stats, error) {
	img, err := source.Open(ctx, ref)
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, err
	}
	return catalogFromImage(ref, img)
}

// catalogFromImage builds a Target the way syft does for the same image: the
// distro from /etc/os-release, packages from /lib/apk/db/installed, and each
// package's Location.LayerDigest from the layer the file it was read from
// actually belongs to (apkdb.Parse cannot set this itself — it never sees a
// layer, only a reader).
//
// A missing os-release, or one whose distro has no ecosystem, is not an
// error: the packages below are still cataloged, with an empty Ecosystem, so
// the matcher and report already treat them as not evaluated (D11). Returning
// early here with a nil error and an empty Target would instead print "no
// known vulnerabilities found" — a clean result for a scan that checked
// nothing.
//
// Zero cataloged packages IS an error, though, unlike an empty Ecosystem — an
// empty database (no /lib/apk/db/installed at all, or none of it readable)
// has no package to attach an empty Ecosystem to for the matcher/report to
// mark not-evaluated the way an unkeyed one is. Inventing a placeholder
// component to route around that would fabricate the exact thing
// cyclonedx.Stats' own contract forbids: a package that was never there
// becomes indistinguishable from one with no vulnerabilities. An explicit
// error naming what was looked for is the honest answer, and Run already maps
// a catalog error to exit 2 with stdout untouched.
func catalogFromImage(ref string, img *source.Image) (pkgmeta.Target, cyclonedx.Stats, error) {
	files, err := img.Files(append([]string{osReleasePath, apkDBPath, dpkgDBPath}, rpmDBPaths()...))
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, err
	}

	var (
		target    pkgmeta.Target
		ecosystem string
	)
	if f, ok := files[osReleasePath]; ok {
		d, err := osrelease.Parse(bytes.NewReader(f.Data))
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", osReleasePath, err)
		}
		target.Distro = &d
		if eco, err := d.Ecosystem(); err == nil {
			ecosystem = eco
		}
		// On error ecosystem stays "": apk packages are cataloged unkeyed below,
		// so the matcher reports them as skipped with a reason. Guessing a
		// substitute key here would turn "we cannot check this" into "this is
		// clean" — exactly the false negative D11 exists to prevent.
	}

	// Dispatched on which database the image actually carries, not on what
	// os-release claimed. An image may have neither, and one that has a
	// database whose distro has no ecosystem is still worth cataloging unkeyed
	// — the matcher reports those as skipped rather than clean.
	var pkgs []pkgmeta.Package
	var diffID string
	var skippedRecords int
	rpmFound, hasRPM := findRPMDB(files)
	switch {
	case files[apkDBPath].Data != nil:
		f := files[apkDBPath]
		p, err := apkdb.Parse(bytes.NewReader(f.Data), ecosystem)
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", apkDBPath, err)
		}
		pkgs, diffID = p, f.DiffID
	case files[dpkgDBPath].Data != nil:
		f := files[dpkgDBPath]
		p, err := dpkgdb.Parse(bytes.NewReader(f.Data), ecosystem)
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", dpkgDBPath, err)
		}
		pkgs, diffID = p, f.DiffID
	case hasRPM:
		// D43. The inventory is read and no verdict follows: ecosystem is ""
		// for every RPM distro because Distro.Ecosystem() has no key for them,
		// so the matcher reports all of these as skipped and Trustworthy()
		// takes the scan to exit 2. That is the whole design — the OSV Red Hat
		// feed is errata-only and cannot express "affected, will not fix", so a
		// verdict built on it would be confidently clean about 39,372 CVEs it
		// has never seen.
		if rpmFound.ndbPath != "" {
			return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf(
				"%s carries an ndb rpm database at %s (openSUSE and SLES), which this build "+
					"does not read; there is no SUSE advisory source for it to serve",
				ref, rpmFound.ndbPath)
		}
		// Two backends, one header parser. Which one an image carries is a
		// property of its release, not of anything the caller asked for: RHEL 8
		// and older and Amazon Linux 2 keep a BerkeleyDB hash file, RHEL 9 and
		// newer a SQLite one, and the packages that come out are identical
		// either way.
		var (
			res  rpmdb.Result
			err  error
			f    source.FileFromLayer
			path string
		)
		if rpmFound.bdbPath != "" {
			path = rpmFound.bdbPath
			f = files[path]
			res, err = rpmdb.ReadBDB(f.Data, ecosystem, path)
		} else {
			path = rpmFound.sqlitePath
			f = files[path]
			res, err = rpmdb.ReadSQLite(f.Data, rpmFound.walSize, ecosystem, path)
		}
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, err
		}
		pkgs, diffID, skippedRecords = res.Packages, f.DiffID, len(res.Skipped)
	}
	if len(pkgs) == 0 {
		// Naming the shapes that were looked for, and the ones that are known
		// and not supported, because "no database" and "a database this build
		// cannot read" are different facts and only the second tells the reader
		// what to do about it.
		//
		// An RPM distro with no database at all gets its own sentence. It is
		// the most likely false negative in this whole path: /var/lib/rpm is a
		// symlink on RHEL 10, Fedora and CentOS Stream 10, so a probe that
		// missed the relocated directory would find nothing — and without this
		// error, "nothing" is a clean image.
		if target.Distro != nil && rpmFamilies[target.Distro.ID] {
			return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf(
				"%s reports itself as %q, an RPM distribution, but none of %v holds an rpm "+
					"database; this result cannot be trusted",
				ref, target.Distro.ID, rpmDBPaths())
		}
		return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf(
			"no supported package database found in %s (looked for %s, %s and an rpm database "+
				"under %v; a distroless image keeps its database in var/lib/dpkg/status.d, "+
				"which this build cannot read)", ref, apkDBPath, dpkgDBPath, rpmDBDirs)
	}
	for i := range pkgs {
		for j := range pkgs[i].Locations {
			pkgs[i].Locations[j].LayerDigest = diffID
		}
	}
	target.Packages = pkgs

	// A record whose header could not be read is a package whose version we do
	// not know, which is the field that already means exactly that and already
	// feeds Summary.TargetIncomplete (D36). Counting it anywhere else, or not
	// counting it, would let an image with three damaged headers report the
	// same as one with none.
	return target, cyclonedx.Stats{
		Cataloged:        len(pkgs),
		Components:       len(pkgs) + skippedRecords,
		SkippedNoVersion: skippedRecords,
	}, nil
}

// redHatFindings reports whether any finding was matched under a Red Hat
// ecosystem key, which is what earns the mainline-errata caveat above.
//
// Keyed on the ecosystem of the FINDING rather than on Target.Distro, so an
// SBOM carrying Red Hat components gets the same caveat as an image scan: the
// divergence belongs to the data the match used, not to how the inventory was
// obtained.
func redHatFindings(findings []matcher.Finding) bool {
	for _, f := range findings {
		if strings.HasPrefix(f.Package.Ecosystem, "Red Hat:") {
			return true
		}
	}
	return false
}
