package pkgmeta

// UbuntuReleases returns a private copy of the mainline codename-to-YY.MM
// table used by both the Ubuntu tracker and VEX product matching.
// Coverage includes every LTS back to the oldest release D53 itself
// tests (trusty, 14.04) plus the interim releases confirmed live in the
// tracker's own tree on 2026-08-21 -- oracular, plucky and questing per the
// design brief, and resolute alongside them, confirmed by
// esm-apps-resolute-supported.txt existing in that same tree listing (one
// letter past questing, and the samples show real package data against it --
// "resolute_pcre3: DNE", "resolute_openssl: released (3.0.8-1ubuntu2)" --
// not the placeholder shape an unreleased codename would have). stonking is
// 26.10, added 2026-11-04 (QA): the tracker's own scripts/cve_lib.py orders
// it right after resolute and before tenacious (the development release),
// releases.ubuntu.com lists 26.10/, and OSV's Ubuntu:26.10 key already held
// 16,289 fix-less ranges in the 2026-11-01 artifact -- every one of them
// without a fix state, because its stonking_ rows were unknown-codename
// tuples. D157's publish guard cannot see that gap: a key published at zero
// stays at zero.
//
// An EOL'd interim (kinetic, lunar, mantic, ...) deliberately has no entry.
// No image this project can evaluate reports one of those as its release --
// pkgmeta.Distro.Ecosystem only ever resolves a VERSION_ID that exists on a
// running system -- so a stanza line naming one becomes an "unknown
// codename" tuple: counted by parseUbuntuTrackerFile, and harmless. The same
// choice D75 made for Fedora's own EOL'd releases.
func UbuntuReleases() map[string]string {
	return map[string]string{
		"trusty":   "14.04",
		"xenial":   "16.04",
		"bionic":   "18.04",
		"focal":    "20.04",
		"jammy":    "22.04",
		"noble":    "24.04",
		"oracular": "24.10",
		"plucky":   "25.04",
		"questing": "25.10",
		"resolute": "26.04",
		"stonking": "26.10",
	}
}
