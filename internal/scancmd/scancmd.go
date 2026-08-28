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
	"time"

	"github.com/kun9497/assay/internal/cataloger/apkdb"
	"github.com/kun9497/assay/internal/cataloger/bitnamidb"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/dirscan"
	"github.com/kun9497/assay/internal/cataloger/dpkgdb"
	"github.com/kun9497/assay/internal/cataloger/gobinary"
	"github.com/kun9497/assay/internal/cataloger/jar"
	"github.com/kun9497/assay/internal/cataloger/osrelease"
	"github.com/kun9497/assay/internal/cataloger/pacmandb"
	"github.com/kun9497/assay/internal/cataloger/rpmdb"
	"github.com/kun9497/assay/internal/cataloger/spdx"
	"github.com/kun9497/assay/internal/ignore"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/source"
	"github.com/kun9497/assay/internal/store"
	"github.com/kun9497/assay/internal/vex"
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
	// FailOnKEV makes a finding CISA's Known Exploited Vulnerabilities
	// catalog lists trip the scan on its own, exit 1 (D86) — the identical
	// shape to FailOnUnfixable one field up: a fact about the finding that
	// no severity threshold expresses, checked through
	// matcher.Finding.KnownExploited() rather than a band comparison.
	FailOnKEV bool
	// FailOnEPSS gates on FIRST.org's exploit-probability score: exit 1 when
	// any finding's MaxEPSS() is at or above this threshold.
	//
	// A pointer for the reason Options.FailOn is one — 0.0 is a real,
	// requestable threshold ("fail on anything EPSS has scored at all") and
	// also float64's zero value, so it cannot mean "not set" without
	// colliding with that explicit request.
	//
	// A finding with no EPSS row at all NEVER trips this: MaxEPSS's own
	// ok == false already keeps D17's shape (absent stays absent), so the
	// verdict check must read ok, never just compare the returned float
	// against zero.
	FailOnEPSS *float64
	// FailOnEOL makes a scan whose TARGET distro release is past its own
	// end-of-life date trip exit 1 (D87) — a fact about the target rather
	// than about any one finding, the same shape FailOnKEV and FailOnUnfixable
	// already are one level up: no severity threshold expresses "this base
	// image is unsupported".
	//
	// Never trips on its own when there is no answer: Target.Distro nil (every
	// SPDX SBOM, D84), a release this build cannot key, or a database with no
	// EOL data at all (built before D87, or EOL_ENABLE=0) all warn on stderr
	// instead (verdict's own doc comment) — the D17 "absent stays absent"
	// discipline applied to a target-level fact instead of a per-finding one.
	FailOnEOL bool
	// Output selects the renderer: "" and "table" both mean the human table
	// (Options{}'s zero value must reproduce today's behaviour exactly, the
	// same rule Options.FailOn* already follows), "json" means the stable
	// document report.JSON writes (D18: the flag name follows grype's own
	// --output). The CLI layer (cmd/assay) rejects any other value before
	// Run ever sees it — an invalid value here would be a silently wrong
	// renderer choice, not a silently-ignored flag, but the earlier a typo
	// surfaces the better.
	Output string
	// Version reaches the SARIF renderer and nothing else (D55): a SARIF
	// file is read detached from the command that produced it, so the
	// document has to say what scanned. The TARGET is Run's own parameter
	// and needs no option.
	Version string
	// DBMaxAge refuses a scan against vulnerability data older than this
	// (D59). Zero disables the check, which is the default: the right
	// number depends on how the caller runs `db update`, and inventing one
	// here would be a policy nobody chose.
	DBMaxAge time.Duration
	// Explain, when non-empty, selects one advisory to explain instead of
	// rendering the table or JSON: its own ID, or any alias/upstream
	// identifier it carries (D3) — whatever a reader would have grepped the
	// table's ALIASES column for. This is D10 made visible: which range
	// matched, which comparer decided it, and which name reached the
	// advisory (D8), the exact fields Evidence and MatchedName exist to
	// carry. It does not change the --fail-on* verdict below: explain mode
	// picks the renderer, not the exit code.
	Explain string
	// IgnoreFile is the path to a .assay.yaml ignore config, from --config.
	// Empty means "discover .assay.yaml in the working directory, and run
	// without one if there is none" — a project that has never written an
	// ignore file scans exactly as before. A file that is named but cannot
	// be read or parsed fails the scan (exit 2): a malformed waiver list is
	// a mistake the caller wants told about, not one that silently waives
	// nothing.
	IgnoreFile string
	// VEXFiles is every path passed via --vex (D104), repeatable and applied
	// in the order given — grype's own flag name (D18), so migrating a
	// pipeline that already gates on grype's VEX support costs nothing but
	// the binary. Each document's not_affected/fixed statements suppress the
	// findings they exonerate, moving them into res.Suppressed exactly like
	// an ignore rule does; a document that cannot be read or parsed fails
	// the scan (exit 2) on IgnoreFile's own reasoning above — an unreadable
	// waiver is untrustworthy input, not "nothing waived".
	VEXFiles []string
}

// The two files an image cataloger reads, named as they appear as tar entries
// (no leading slash) — which is also the form Image.Files normalises its own
// keys to, so a lookup with a leading slash would just miss.
const (
	osReleasePath = "etc/os-release"
	apkDBPath     = "lib/apk/db/installed"
	// dpkgDBPath is the ordinary Debian and Ubuntu database: one file holding
	// every stanza. Never glob status*: debian:* ships status-old holding a
	// full duplicate of every stanza, and matching it would double the
	// inventory.
	dpkgDBPath = "var/lib/dpkg/status"
	// dpkgStatusDir is the same database as a DIRECTORY of one stanza per
	// package, which is what distroless images ship (D54). Its contents are
	// named after the packages, so unlike every other path here it cannot be
	// asked for by name — Image.FilesUnder discovers it.
	//
	// Tried only when the single-file form is absent. An image carrying both
	// is not a shape anything ships, and preferring the file keeps the
	// ordinary Debian path exactly as it was.
	dpkgStatusDir = "var/lib/dpkg/status.d"
	// apkDBPathUsrLib is where Wolfi and Chainguard images physically store
	// the apk database (D88), behind a `lib -> usr/lib` symlink. Image.Files
	// follows a symlink that IS the requested tar entry; it does not follow
	// one on a DIRECTORY COMPONENT of a requested path, the same limitation
	// rpmDBDirs' own comment below names for /var/lib/rpm on RHEL 10 and
	// Fedora 36+. A probe of apkDBPath alone therefore finds nothing at all
	// in these images' layers, and without apkDBPaths below, "no supported
	// package database found" is D43's failure one distro further in.
	apkDBPathUsrLib = "usr/lib/apk/db/installed"
	// apkDBPathVarLib is where BellSoft's Alpaquita Linux and Hardened
	// Containers images store the apk database (D95) — a real regular file
	// at the FHS-standard location, NOT a directory-component symlink the
	// way apkDBPathUsrLib's target is: these images ship no /lib at all
	// (verified against a real pulled bellsoft/alpaquita-linux-base image,
	// 2026-08-26), so a probe of apkDBPath or apkDBPathUsrLib alone finds
	// nothing in their layers — the identical "no supported package
	// database found" failure D88 fixed for Wolfi/Chainguard one path over,
	// for a distro that does not even need the symlink-following workaround
	// that path needed.
	apkDBPathVarLib = "var/lib/apk/db/installed"
	// pacmanLocalDir is Arch Linux's pacman local package database (D97): a
	// DIRECTORY OF DIRECTORIES, one subdirectory per installed package
	// (var/lib/pacman/local/<name>-<version>-<pkgrel>/desc), unlike every
	// other database probed here. Its contents are named after the
	// packages, the same reason dpkgStatusDir cannot be asked for by name
	// either — source.FilesNamed discovers the desc files one level deeper
	// than source.FilesUnder reaches. The directory also carries a sibling
	// FILE, ALPM_DB_VERSION, which FilesNamed excludes by construction: it
	// is a direct child of local/, not one level deeper, and is not named
	// "desc" either.
	pacmanLocalDir = "var/lib/pacman/local"
	// cleanStartMarkerPackage is D101's marker probe: CleanStart (apk-based
	// hardened containers) ships NO /etc/os-release at all — verified
	// against 11/11 real pulled images -- so its presence in the apk
	// installed database (the same file every Alpine-family image is
	// already read from) is the only signal available to route a
	// no-os-release image here. Measured present, by this exact name, in
	// 11/11 images (busybox, kafka, mariadb, mysql, nginx, node, postgres,
	// python, redis, ruby, rust). Narrow on purpose: the probe below matches
	// this literal name only, never a "clnstrt-*" prefix, so a plain Alpine
	// image that happens to ship no such package is never misrouted.
	cleanStartMarkerPackage = "clnstrt-baselayout"
	// bitnamiDir is where Bitnami installs every application it packages
	// (D99). Its own markers are discovered rather than asked for by exact
	// name (source.FilesMatching, below) for the same reason
	// dpkgStatusDir's and pacmanLocalDir's contents are: they are named
	// after the component they describe.
	bitnamiDir = "opt/bitnami"
	// bitnamiSPDXPrefix and bitnamiSPDXSuffix are D99's own marker shape:
	// "/opt/bitnami/**/.spdx-<component>.spdx", an SPDX 2.3 JSON document
	// despite the ".spdx" extension. A same-named ".json" symlink sits
	// beside every real marker on a real image; it is excluded by this
	// pattern alone (its suffix is ".json"), with no symlink-specific
	// handling needed on top.
	bitnamiSPDXPrefix = ".spdx-"
	bitnamiSPDXSuffix = ".spdx"
	// bitnamiLegacyPath is the frozen-image fallback (D99): a flat
	// name -> {version, ...} map with no bundled-library detail, carried
	// only by older "bitnamilegacy" images alongside their own SPDX
	// markers.
	bitnamiLegacyPath = "opt/bitnami/.bitnami_components.json"
)

// apkDBPaths is every tar entry the apk probe asks for, traditional path
// first.
var apkDBPaths = []string{apkDBPath, apkDBPathUsrLib, apkDBPathVarLib}

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

// rpmDBFiles are the file names inside those directories, one per backend, all
// three read. Packages is BerkeleyDB (RHEL 8 and older, Amazon Linux 2),
// rpmdb.sqlite is SQLite (RHEL 9 and newer), and Packages.db is ndb (D76),
// which only openSUSE and SLES use.
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
	// D96: unlike "mariner"/"azurelinux" (pre-seeded since D43, years before
	// either had a real ecosystem or provider), "photon" was genuinely
	// absent here until this slice -- verified by grep before adding it,
	// per D94's own review finding that a pre-seeded entry can sit
	// unexercised for years. TestCatalogFromImage_PhotonDistroWithNoDatabase
	// is the held test that proves this entry is actually reached.
	"photon": true,
	// D98: same discipline as "photon" -- verified by grep before adding it
	// rather than assumed pre-seeded. Project Hummingbird's rpmdb is SQLite
	// at usr/lib/sysimage/rpm, the same path/backend RHEL 9+ uses, and
	// os-release lives at usr/lib/os-release with the ordinary etc symlink
	// -- no new probe path was needed, only this entry so a missing
	// database reports the specific error rather than the vaguer one.
	"hummingbird": true,
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
	ndbPath string // ndb (D76): openSUSE and SLES only
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

// findAPKDB picks the apk database out of the probed files, preferring the
// traditional path over the physical usr/lib one D88 added -- an image
// carrying both is not a shape anything ships, and preferring the
// traditional path keeps the ordinary Alpine path exactly as it was, the
// same call dpkgStatusDir's own comment makes for status vs status.d.
func findAPKDB(files map[string]source.FileFromLayer) (source.FileFromLayer, string, bool) {
	for _, p := range apkDBPaths {
		if f, ok := files[p]; ok && f.Data != nil {
			return f, p, true
		}
	}
	return source.FileFromLayer{}, "", false
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

	case source.TargetJar:
		// jar.Parse returns the raw package slice, not a pkgmeta.Target
		// (D70's fixed signature, shared with every per-manifest cataloger
		// dirscan dispatches to) - wrapped here the same way dirscan.Parse's
		// own callers never see, since a jar scan has exactly one manifest
		// and no merge to do.
		pkgs, stats, err := jar.Parse(path)
		if err != nil {
			// jar.Parse's own error already names path.
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		// Distro stays nil - a jar is not an operating system (D7).
		inventory, cat = pkgmeta.Target{Packages: pkgs}, stats

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
		// Classify only decided "this is some kind of SBOM" (D84) — CycloneDX
		// and SPDX share one TargetKind, whether that kind came from content
		// sniffing or from an explicit sbom: prefix, which bypasses content
		// sniffing entirely (:53's table). So the choice of parser is made
		// again here, by the same content sniff LooksLikeSPDX exports for
		// exactly this, before the file is opened for real.
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(stderr, "error: open %s: %v\n", path, err)
			return 2
		}
		defer f.Close()

		var (
			t     pkgmeta.Target
			stats cyclonedx.Stats
		)
		if source.LooksLikeSPDX(path) {
			t, stats, err = spdx.Parse(f)
		} else {
			t, stats, err = cyclonedx.Parse(f)
		}
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

	// Read once, unconditionally: DBMaxAge below and the D87 EOL lookup
	// further down both need it, and openReadOnly already proved this
	// exact read succeeds once before store.Open ever returns (its own doc
	// comment) — there is no cheaper "only if a flag needs it" version that
	// does not cost a second round trip through the same bucket.
	m, err := db.Meta()
	if err != nil {
		fmt.Fprintf(stderr, "error: read database metadata: %v\n", err)
		return 2
	}

	// D59. Before matching, not after: a scan that will be refused for age
	// should not spend the time, and a summary printed first would be a
	// verdict from data the next line calls untrustworthy.
	if opts.DBMaxAge > 0 {
		if code := checkDBAge(m, opts.DBMaxAge, time.Now(), stderr); code != 0 {
			return code
		}
	}

	res, err := matcher.New(db).Match(inventory)
	if err != nil {
		fmt.Fprintf(stderr, "error: match: %v\n", err)
		return 2
	}

	// Ignore rules (the VEX/ignore feature) waive findings the user has
	// judged irrelevant, moving them into res.Suppressed. This runs BEFORE
	// the renderers and the verdict: a waived finding must not reach the
	// table or trip --fail-on, but every renderer still shows it as a
	// counted, reasoned block — the matcher stayed pure, and suppression is
	// visible, never silent (matcher.Result.Suppressed's own doc comment).
	if code := applyIgnoreRules(&res, opts.IgnoreFile, stderr); code != 0 {
		return code
	}

	// D104. Runs AFTER applyIgnoreRules, deliberately: a finding
	// .assay.yaml already waived is gone from res.Findings by this point, so
	// no VEX document re-evaluates it — one suppression, one reason, and
	// whichever mechanism ran first wins, rather than a finding silently
	// carrying two waivers or the second one overwriting the first's reason.
	if code := applyVEX(&res, opts.VEXFiles, stderr); code != 0 {
		return code
	}

	// D87. Computed unconditionally — not only when --fail-on-eol is set —
	// because the table/JSON/SARIF renderers surface the fact regardless of
	// the gate (the same shape KEV membership already is: the table marks
	// it whether or not --fail-on-kev was ever passed). clockNow(), not
	// time.Now() directly, is the seam a test pins to drive both sides of
	// the EOLFrom boundary without waiting for a real date to pass.
	eolStatus := lookupEOL(inventory.Distro, m.EOL, clockNow())

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
		sum, err = report.JSON(stdout, res, cat, eolStatus)
		if err != nil {
			fmt.Fprintf(stderr, "error: write report: %v\n", err)
			return 2
		}
	case opts.Output == "sarif":
		// D55. The target is passed so a result message can name what was
		// scanned: a SARIF file is read in a web UI detached from the
		// command that produced it, where "libc6 is affected" alone does
		// not say which image.
		sum, err = report.SARIF(stdout, res, cat, target, opts.Version, eolStatus)
		if err != nil {
			fmt.Fprintf(stderr, "error: write report: %v\n", err)
			return 2
		}
	default:
		sum, err = report.Table(stdout, res, cat, eolStatus)
		if err != nil {
			fmt.Fprintf(stderr, "error: write report: %v\n", err)
			return 2
		}
	}
	// D87: --fail-on-eol asked a question this scan could not answer.
	// Naming WHY, never a silent skip and never treated as a false trip —
	// the gate itself (verdict, below) simply does not fire when
	// eolStatus.Known is false, and this is the only place that says so.
	// Gated on the FLAG, unlike the Red Hat mainline-errata note above: an
	// SBOM with no distro identity is routine and not worth a caveat on
	// every scan, but a caller who explicitly asked this question and got
	// no answer needs to know their gate is not doing anything.
	if opts.FailOnEOL && !eolStatus.Known {
		fmt.Fprintf(stderr, "warning: EOL unknown: %s\n", eolStatus.Reason)
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
	return verdict(opts, sum, res.Findings, eolStatus)
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

// applyIgnoreRules loads the ignore config and moves waived findings from
// res.Findings into res.Suppressed. It is a no-op (exit 0, nothing changed)
// when no config is named and none is discovered — a project with no
// .assay.yaml scans exactly as before. A named-but-unreadable or malformed
// config fails the scan at exit 2, on IgnoreFile's own reasoning: a broken
// waiver list is a mistake to surface, not one to run past.
func applyIgnoreRules(res *matcher.Result, ignoreFile string, stderr io.Writer) int {
	path := ignoreFile
	if path == "" {
		// No --config: look for the default in the working directory, and
		// run without one if there is none.
		wd, err := os.Getwd()
		if err != nil {
			return 0 // cannot look; behave as if there is no config
		}
		p, ok := ignore.Discover(wd)
		if !ok {
			return 0
		}
		path = p
	}
	cfg, err := ignore.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	warn := func(msg string) { fmt.Fprintf(stderr, "warning: %s\n", msg) }
	kept, suppressed := cfg.Apply(res.Findings, time.Now(), warn)
	res.Findings = kept
	res.Suppressed = suppressed
	if len(suppressed) > 0 {
		fmt.Fprintf(stderr, "%d finding(s) suppressed by %s\n", len(suppressed), path)
	}
	return 0
}

// applyVEX loads every --vex document in order and moves the findings each
// one exonerates from res.Findings into res.Suppressed, the same shape
// applyIgnoreRules already established. It is a no-op when no --vex was
// given — VEXFiles is nil and the loop below never runs, so a scan with no
// VEX input behaves exactly as before D104. A document that cannot be read
// or parsed fails the scan at exit 2 with its path named in the error, on
// the identical "an unreadable waiver is untrustworthy input" reasoning
// applyIgnoreRules already applies to a malformed .assay.yaml (D11).
//
// Each document is applied against whatever res.Findings still holds after
// the documents processed before it — so a later --vex path can only
// suppress what an earlier one left behind, never re-suppress what it
// already waived, matching applyIgnoreRules' own "ignore rules run first"
// ordering one level down.
func applyVEX(res *matcher.Result, paths []string, stderr io.Writer) int {
	warn := func(msg string) { fmt.Fprintf(stderr, "warning: %s\n", msg) }
	for _, path := range paths {
		doc, err := vex.Load(path)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		kept, suppressed := doc.Apply(res.Findings, warn)
		res.Findings = kept
		res.Suppressed = append(res.Suppressed, suppressed...)
		if len(suppressed) > 0 {
			fmt.Fprintf(stderr, "%d finding(s) suppressed by VEX (%s)\n", len(suppressed), path)
		}
	}
	return 0
}

func verdict(opts Options, sum report.Summary, findings []matcher.Finding, eol report.EOLStatus) int {
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
	// D86. Checked beside the unfixable gates above, and reading the count
	// Summarize already computed for the same reason those do: the table's
	// own "known-exploited" count and this gate must not drift apart on what
	// counts as one.
	if opts.FailOnKEV && sum.KnownExploited > 0 {
		return 1
	}
	// D87. Fires only when eol.Known is true AND eol.EOL is true — never on
	// an unanswered lookup (Run's own disclosure already warned about that
	// case on stderr, before verdict was ever called), which is the D17
	// "absent stays absent" discipline applied to a target-level fact
	// instead of a per-finding one: a flag that could trip on "we don't
	// know" would punish every SBOM with no distro identity the same as an
	// image that is genuinely unsupported.
	if opts.FailOnEOL && eol.Known && eol.EOL {
		return 1
	}
	// D86. No precomputed count to read here, unlike FailOnKEV just above:
	// the threshold is a caller-supplied number, not a fixed classification
	// like KnownExploited or WontFix, so Summarize has nothing it could have
	// counted in advance. Absent stays absent (D17's shape) because MaxEPSS's
	// own ok is false for a finding no source scored, and the loop below
	// only ever compares the ones that came back true.
	if opts.FailOnEPSS != nil {
		for _, f := range findings {
			if v, ok := f.MaxEPSS(); ok && v >= *opts.FailOnEPSS {
				return 1
			}
		}
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
	wantPaths := append([]string{osReleasePath, dpkgDBPath}, apkDBPaths...)
	files, err := img.Files(append(wantPaths, rpmDBPaths()...))
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, err
	}
	// rpm and apk detection is cheap (map lookups against the single-shot
	// Files() result above), computed here rather than just before the
	// switch below, so it can also gate the pacman probe further down
	// without paying for a second full layer pass on every image that is
	// neither Debian nor Arch.
	rpmFound, hasRPM := findRPMDB(files)
	apkFound, apkPath, hasAPK := findAPKDB(files)

	// Only when the single-file database is absent, so an ordinary Debian
	// image pays nothing for this: FilesUnder is a second full pass over
	// every layer (D54).
	var statusD map[string]source.FileFromLayer
	var statusDLinks int
	if files[dpkgDBPath].Data == nil {
		statusD, statusDLinks, err = img.FilesUnder(dpkgStatusDir)
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, err
		}
	}
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, err
	}

	// D97. Only when nothing else has already been found: FilesNamed is
	// another full pass over every layer, the identical cost D54's own
	// comment above accepts for status.d, paid here only by an image that
	// is not apk-, dpkg- or rpm-based -- which an Arch image, by
	// construction, never is.
	var pacmanFiles map[string]source.FileFromLayer
	var pacmanLinks int
	if !hasAPK && files[dpkgDBPath].Data == nil && len(statusD) == 0 && !hasRPM {
		pacmanFiles, pacmanLinks, err = img.FilesNamed(pacmanLocalDir, "desc")
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, err
		}
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
	} else if hasAPK {
		// D101. No /etc/os-release at all is CleanStart's ordinary shape, not
		// an error — but ONLY when there is truly no os-release entry: this
		// branch is `else if`, reached only when the `if` above found none,
		// so an image that legitimately has a real os-release is always
		// routed by it and never by this marker, even if it happened to also
		// carry the marker package. That precedence is deliberate: CleanStart
		// itself never ships both, so this is a "which wins" decision for a
		// shape that should not occur, resolved in favor of never letting a
		// heuristic override a real, positive statement the image made about
		// itself.
		isCleanStart, err := apkdb.HasPackage(bytes.NewReader(apkFound.Data), cleanStartMarkerPackage)
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("probe %s for CleanStart marker: %w", apkPath, err)
		}
		if isCleanStart {
			d := pkgmeta.Distro{ID: "cleanstart"}
			target.Distro = &d
			if eco, err := d.Ecosystem(); err == nil {
				ecosystem = eco
			}
		}
	}

	// Dispatched on which database the image actually carries, not on what
	// os-release claimed. An image may have neither, and one that has a
	// database whose distro has no ecosystem is still worth cataloging unkeyed
	// — the matcher reports those as skipped rather than clean.
	var pkgs []pkgmeta.Package
	var diffID string
	var skippedRecords int
	switch {
	case hasAPK:
		p, err := apkdb.Parse(bytes.NewReader(apkFound.Data), ecosystem)
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", apkPath, err)
		}
		pkgs, diffID = p, apkFound.DiffID
	case files[dpkgDBPath].Data != nil:
		f := files[dpkgDBPath]
		p, err := dpkgdb.Parse(bytes.NewReader(f.Data), ecosystem)
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", dpkgDBPath, err)
		}
		pkgs, diffID = p, f.DiffID
	case len(statusD) > 0:
		// D54. One stanza per file, parsed in sorted order so two scans of one
		// image agree — FilesUnder returns a map, and a map's iteration order
		// reaching the report would make every run a different document.
		//
		// diffID is taken from the layer the FIRST stanza came from. A
		// distroless image's status.d is written by one COPY, so in practice
		// every stanza shares a layer; where it does not, the per-package
		// Location already carries the file it came from, which is the
		// finer-grained answer a reader wants anyway.
		for _, name := range source.SortedNames(statusD) {
			f := statusD[name]
			p, err := dpkgdb.ParseStanza(bytes.NewReader(f.Data), ecosystem, name)
			if err != nil {
				return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", name, err)
			}
			if diffID == "" {
				diffID = f.DiffID
			}
			pkgs = append(pkgs, p...)
		}
		// A symlink under status.d is a stanza this build did not read, so it
		// is counted as a package whose version is unknown rather than
		// dropped. Zero on every distroless image measured; if that ever
		// changes, the scan says how many rather than quietly shrinking the
		// inventory (D36's rule, applied to a shape D54 introduces).
		skippedRecords += statusDLinks
	case hasRPM:
		// D43, extended to the third container format by D76. The inventory
		// is read regardless of whether pkgmeta.Distro.Ecosystem() can key
		// it: a distro this build has no advisory feed for (centos,
		// openEuler, azurelinux, mariner, opensuse-tumbleweed) resolves
		// ecosystem "", the matcher reports it skipped, and Trustworthy()
		// takes the scan to exit 2 rather than a confidently clean verdict
		// built on nothing.
		//
		// An ndb image (openSUSE, SLES) no longer takes that path by
		// default: D76 closed "we cannot even list its packages", and D77
		// closed the advisory half that comment left open — `sles` and
		// `opensuse-leap` now resolve a real key (suse.foldKey's fold on the
		// provider side, pkgmeta.Distro.Ecosystem's "SLES:"/"openSUSE
		// Leap:" case on this side) and are matched against SUSE's own CSAF
		// VEX feed, the same errata-plus-no-fix-states shape D47-D52 built
		// for Red Hat. opensuse-tumbleweed still resolves nothing — a
		// rolling release has no stable release axis to key advisories on —
		// so it still takes the catalogued-but-not-evaluated path this
		// comment originally described for the whole ndb family.
		//
		// Three backends, one header parser. Which one an image carries is a
		// property of its release, not of anything the caller asked for:
		// RHEL 8 and older and Amazon Linux 2 keep a BerkeleyDB hash file,
		// RHEL 9 and newer a SQLite one, openSUSE and SLES an ndb one, and
		// the packages that come out are identical either way.
		var (
			res  rpmdb.Result
			err  error
			f    source.FileFromLayer
			path string
		)
		switch {
		case rpmFound.bdbPath != "":
			path = rpmFound.bdbPath
			f = files[path]
			res, err = rpmdb.ReadBDB(f.Data, ecosystem, path)
		case rpmFound.ndbPath != "":
			path = rpmFound.ndbPath
			f = files[path]
			res, err = rpmdb.ReadNDB(f.Data, ecosystem, path)
		default:
			path = rpmFound.sqlitePath
			f = files[path]
			res, err = rpmdb.ReadSQLite(f.Data, rpmFound.walSize, ecosystem, path)
		}
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, err
		}
		pkgs, diffID, skippedRecords = res.Packages, f.DiffID, len(res.Skipped)
	case len(pacmanFiles) > 0:
		// D97. One desc file per package, parsed in sorted order for the
		// same reason status.d's own loop above is: FilesNamed returns a
		// map, and a map's iteration order reaching the report would make
		// every run a different document.
		//
		// diffID is taken from the layer the FIRST desc file came from —
		// status.d's own reasoning applies unchanged: a pacman database is
		// written by one image build, so in practice every desc file shares
		// a layer; where it does not, the per-package Location already
		// carries the file it came from, the finer-grained answer a reader
		// wants anyway.
		for _, name := range source.SortedNames(pacmanFiles) {
			f := pacmanFiles[name]
			p, err := pacmandb.ParseDesc(bytes.NewReader(f.Data), ecosystem, name)
			if err != nil {
				return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", name, err)
			}
			if diffID == "" {
				diffID = f.DiffID
			}
			pkgs = append(pkgs, p...)
		}
		// A symlink under a pacman package directory is a desc file this
		// build did not read, so it is counted as a package whose version
		// is unknown rather than dropped — status.d's own reasoning again
		// (D54, D36).
		skippedRecords += pacmanLinks
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
			"no supported package database found in %s (looked for %v, %s, %s/, %s/*/desc "+
				"and an rpm database under %v)",
			ref, apkDBPaths, dpkgDBPath, dpkgStatusDir, pacmanLocalDir, rpmDBDirs)
	}
	for i := range pkgs {
		for j := range pkgs[i].Locations {
			pkgs[i].Locations[j].LayerDigest = diffID
		}
	}
	target.Packages = pkgs

	// D99: Bitnami app packages are catalogued ALONGSIDE the distro
	// inventory above, not instead of it (D7) — a Bitnami image is a real
	// distro (Photon for current images, Debian for frozen legacy ones)
	// PLUS whatever applications Bitnami installed under /opt/bitnami, and
	// both halves belong in one Target. Unlike the distro switch above,
	// finding no Bitnami markers is not an error: the overwhelming majority
	// of images this build scans are not Bitnami images at all, and
	// /opt/bitnami simply does not exist in them.
	bitnamiPkgs, bitnamiSkipped, err := catalogBitnami(img)
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, err
	}
	target.Packages = append(target.Packages, bitnamiPkgs...)
	skippedRecords += bitnamiSkipped

	// A record whose header could not be read is a package whose version we do
	// not know, which is the field that already means exactly that and already
	// feeds Summary.TargetIncomplete (D36). Counting it anywhere else, or not
	// counting it, would let an image with three damaged headers report the
	// same as one with none.
	return target, cyclonedx.Stats{
		Cataloged:        len(target.Packages),
		Components:       len(target.Packages) + skippedRecords,
		SkippedNoVersion: skippedRecords,
	}, nil
}

// catalogBitnami discovers and parses every Bitnami marker in img (D99),
// merging the SPDX-derived and legacy-JSON-derived inventories into one. It
// always probes for both marker shapes, regardless of what the distro
// switch in catalogFromImage found — an image can be Bitnami-flavoured or
// not independent of which distro backs it, so this is unconditional rather
// than gated on a prior case matching.
//
// The returned int is a symlinked-marker count, counted the same way
// dpkgStatusDir's and pacmanLocalDir's own symlinks are (D54, D36): a marker
// this build did not read is a package whose version is unknown, not a
// package silently dropped from the inventory.
func catalogBitnami(img *source.Image) ([]pkgmeta.Package, int, error) {
	markerFiles, markerLinks, err := img.FilesMatching(bitnamiDir, bitnamiSPDXPrefix, bitnamiSPDXSuffix)
	if err != nil {
		return nil, 0, err
	}
	var spdxPkgs []pkgmeta.Package
	for _, name := range source.SortedNames(markerFiles) {
		f := markerFiles[name]
		pkgs, err := bitnamidb.ParseSPDXMarker(bytes.NewReader(f.Data), name)
		if err != nil {
			return nil, 0, fmt.Errorf("parse %s: %w", name, err)
		}
		for i := range pkgs {
			for j := range pkgs[i].Locations {
				pkgs[i].Locations[j].LayerDigest = f.DiffID
			}
		}
		spdxPkgs = append(spdxPkgs, pkgs...)
	}

	// The legacy fallback is a single exact path, unlike the markers above,
	// so it is asked for by name (source.Image.Files) rather than
	// discovered.
	var legacyPkgs []pkgmeta.Package
	legacyFiles, err := img.Files([]string{bitnamiLegacyPath})
	if err != nil {
		return nil, 0, err
	}
	if f, ok := legacyFiles[bitnamiLegacyPath]; ok {
		legacyPkgs, err = bitnamidb.ParseLegacyComponents(bytes.NewReader(f.Data), bitnamiLegacyPath)
		if err != nil {
			return nil, 0, fmt.Errorf("parse %s: %w", bitnamiLegacyPath, err)
		}
		for i := range legacyPkgs {
			for j := range legacyPkgs[i].Locations {
				legacyPkgs[i].Locations[j].LayerDigest = f.DiffID
			}
		}
	}

	return bitnamidb.Merge(spdxPkgs, legacyPkgs), markerLinks, nil
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
