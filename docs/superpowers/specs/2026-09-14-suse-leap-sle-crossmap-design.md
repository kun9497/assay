# D108 — openSUSE Leap ↔ SLE codestream cross-map

Status: **DRAFT for review** — 2026-09-14
Supersedes nothing. Extends D77 (SUSE CSAF VEX provider) and D91 (LTSS fold).

## Problem

The 2026-09-14 weekly differential breached `leap156`'s `minFindings` floor
(8 < 10). Investigation (captured in PR #130) established it is **not** an assay
regression: both weeks ran the same commit (`d316713`) against the same
digest-pinned `opensuse/leap:15.6` image, so only the nightly-published SUSE
database changed.

What changed upstream, measured against the live CSAF for the two affected CVEs:

- SUSE regenerated the CSAF documents for **CVE-2026-5773** and
  **CVE-2026-7168** on 2026-09-09 / 09-11.
- In the regenerated documents, the **`openSUSE Leap 15.6` product entries are
  gone entirely** — absent from `known_affected`, `fixed`, and `recommended`.
  The SP6 `curl` fix now appears only under
  `SUSE Linux Enterprise Server 15 SP6-LTSS:curl-8.14.1-150600.4.51.1`
  (and `...for SAP Applications 15 SP6`), which D91 folds to `SLES:15.SP6`.
- The four dropped tuples are `curl` + `libcurl4` × {CVE-2026-5773,
  CVE-2026-7168}.

The eight surviving `leap156` findings are all still SUSE-sourced under the
`openSUSE Leap:15.6` key (`curl` itself still matches under CVE-2026-11856), so
Leap 15.6 has not vanished from the feed — it is **aging out gradually**: as SUSE
regenerates each document, that document loses its Leap 15.6 product entries.
The count will keep declining week over week.

Contrast: the `bci156` target (SLE BCI 15.6, keyed `SLES:15.SP6`) *grew* the
same week — it receives the SP6-LTSS data normally via D91. Only the
`openSUSE Leap:15.6` key is losing coverage.

## The grounding fact

openSUSE Leap 15.x is built from the SLE 15 SPx **binary** RPMs (the "Jump" /
closing-the-Leap-gap model since Leap 15.3). Leap 15.6 and SLE 15 SP6 share:

- the **150600 codestream**,
- the **same EVR numbering** — the installed Leap `curl` is
  `8.14.1-150600.4.40.1`, and the SLE-SP6-LTSS fix is `8.14.1-150600.4.51.1`;
  under the shared rpm comparer, `4.40.1 < 4.51.1`, so the finding resolves as a
  correct *fixable* result, not a guess.

So `openSUSE Leap:15.6` and `SLES:15.SP6` describe the **same package universe
and the same version axis** for the shared base packages. This is what makes a
cross-map *valid* rather than a fabrication, and it is why version comparison
needs no new `Comparer` (D9): both ecosystems already resolve through the rpm
comparer.

The user's framing (2026-09-14): *even when a release is EOL, if you scan an
image that still has that package installed, the finding disappearing is the
wrong outcome.* The design's job is to stop the disappearance.

## Decision

Add **D108**: the SUSE provider mirrors a folded SLE codestream key's affected
entries onto the corresponding openSUSE Leap key, so a Leap image is judged
against the SLE codestream it is built from when the feed no longer carries a
native Leap entry.

## Approach — provider-side fold mirror (chosen)

Considered three placements:

| | Where | Verdict |
|---|---|---|
| **A (chosen)** | Provider (`internal/provider/suse/csaf.go`) — mirror the folded SLE key onto the Leap key, reusing `foldKey` + D91's tie-break | Scan path stays a pure lookup (D14); lives beside the folding it extends; no core-type change to `Target`; version comparison already valid |
| B | Matcher — a Leap package with no finding retries the SLE key | Rejected: touches the core matcher (a *do-not-delegate*, high-blast-radius area) and adds cross-ecosystem coupling to a component whose purity is load-bearing |
| C | Cataloger — Leap `Target` carries a secondary ecosystem | Rejected: a `Target` core-type change, the largest blast radius of the three |

A is chosen because the change is contained to the one provider that already
folds many SUSE product names into keys (`foldKey`) and already carries a
same-family tie-break (D91's mainline-wins). D108 is the same *kind* of decision
one layer out: "this folded SLE key also answers this Leap key."

### The mapping

Deterministic, from the SUSE/Leap lifecycle:

```
SLES:15         ->  openSUSE Leap:15.0      (SP0 / GA, slesKey drops the "0")
SLES:15.SP{n}   ->  openSUSE Leap:15.{n}    (n >= 1)
SLES:16.{m}     ->  openSUSE Leap:16.{m}
```

**Only map to Leap releases that actually exist.** SLE 15 SP7 exists but there is
no openSUSE Leap 15.7 (Leap jumped to 16), so mirroring `SLES:15.SP7` would
create a phantom `openSUSE Leap:15.7` key nothing ever scans as. Matching this
provider's "refuse unknown shapes, never guess" discipline (`foldKey`), the
mirror targets only a hardcoded allowlist of Leap releases **derived from the
census** (measurement task M1 below), documented with the measured set and a
revisit trigger, exactly as the `foldKey` regexes are.

### Merge policy — gap-fill (native Leap wins per package)

Within one document, after `convert` has computed the folded SLE key(s) and their
ranges (D91 result included):

- For each folded SLE key that maps to an allowlisted Leap release, and for each
  package under it, emit a **mirrored** `openSUSE Leap:<rel>` affected entry with
  the *same* ranges and fix state **only if the document produced no native Leap
  entry for that same package**.

This is a per-package tie-break analogous to D91's mainline-wins, one ecosystem
out. Its consequences:

- **Aging-out documents** (no native Leap entry — the case this slice exists
  for): the mirror fills the gap. The four vanished `curl`/`libcurl4` findings
  return as fixable at `150600.4.51.1`.
- **Transitional documents** (a native Leap entry *does* exist for the package):
  native wins, no mirror. The finding **does not disappear** — it is present from
  the native entry — so the user's requirement holds. It may lack the SLE fix
  version, which is an enrichment gap, not a disappearance.

Rejected alternative — **union** (merge SLE ranges into the native entry so a
native no-fix row also carries the SLE fix version). It is more D25-complete but
requires per-range provenance (a fixed range and a no-fix range on one `Affected`
from two sources) and a matcher that reconciles them, which is a much larger
change for a case the census (M3) is expected to show is rare. Deferred under
YAGNI; recorded so it is not re-litigated. Gap-fill already satisfies the stated
requirement (no vanished finding).

### Disclosure (explainability, goal #1)

A Leap 15.6 finding sourced from SLE-SP6-LTSS data must say so: the fix
`150600.4.51.1` is an LTSS-channel build a free openSUSE Leap user may not pull
directly. The finding is *true* (the installed binary is vulnerable), but the
remediation carries a caveat the report must not hide.

The mirrored `Affected` carries a new additive field:

```go
// CrossMappedFrom names the ecosystem key this entry was mirrored from
// (D108), e.g. "SLES:15.SP6", or "" for an ordinary entry. openSUSE Leap
// 15.x is built from the SLE 15 SPx binaries on the same codestream, so an
// SLE codestream advisory answers a Leap query for a shared package; this
// field discloses that the fixed version named is the SLE (often LTSS-
// channel) build, which a free Leap user may not obtain directly.
// Additive like ModuleStream/Related -- advisories rebuild from providers
// every db build, so no schema bump.
CrossMappedFrom string `json:"cross_mapped_from,omitempty"`
```

This is the one core-type touch (`advisory.Affected`). It is additive with
direct precedent (`ModuleStream` D80, `Related` D71): a database built before the
field decodes it empty, and the next nightly populates it corpus-wide with no
migration. It flows through the matcher into `Evidence` and every renderer shows
it beside the ecosystem (table, JSON, SARIF, `--explain`) — the same "show the
suppression/source, never hide it" obligation every renderer already carries.

If minimal blast radius is preferred over disclosure, the fallback is to emit the
mirror with no marker (findings return, origin undisclosed). Not recommended —
it trades away goal #1 for the sake of one additive field.

## Data flow

```
document (one CVE)
  -> collectPlatforms / collectPackages           (unchanged)
  -> convert: resolve recommended/known_affected   (unchanged, incl. D91)
       yields folded keys: SLES:15.SP6, openSUSE Leap:15.6, ...
  -> D108 mirror pass (new):
       for each folded SLES:15.SP{n} / SLES:16.{m} key -> leapKey
         if leapKey in allowlist and no native leapKey entry for pkg:
           emit Affected{Ecosystem: leapKey, Name: pkg,
                         Ranges: <copied>, CrossMappedFrom: sleKey}
  -> advisory.Affected[]                            (store, then scan reads)
```

The scan path is untouched: it still reads `openSUSE Leap:15.6` advisories for a
Leap 15.6 image (D14). Some of those advisories now exist because the build
mirrored them.

## Testing

The recurring defects on this project are tested-helper/untested-caller and
guards-that-cannot-fail. The plan follows the caller-first rule verbatim.

1. **Caller-first, observable-effect test written first.** A CSAF fixture with
   *no* native Leap entry and an SLE-SP6 fixed entry for a package must produce a
   `openSUSE Leap:15.6` advisory whose finding, run through the matcher against an
   installed lower EVR, is **fixable** and carries `CrossMappedFrom == "SLES:15.SP6"`.
   Then **delete the mirror emit call** and confirm the suite goes red. (If it
   stays green, only the helper is covered — the exact D55/D53/D59 shape.)
2. **The tie-break's both branches.** Native-present → mirror does *not* fire
   (assert the native finding stands and no `CrossMappedFrom` entry is added);
   native-absent → mirror fires. A mutation that flips the guard must be caught.
3. **The mapping is asserted, not incidental.** Assert the produced key is
   `openSUSE Leap:15.6` for `SLES:15.SP6`; a mutation changing the map to `15.5`
   must go red. Use fixture values that cannot collide (distinct package, CVE,
   and EVR) and assert the rendered ecosystem+version pair, not a substring
   (the D53/D71 collision rule).
4. **The allowlist guard is held.** `SLES:15.SP7` (no Leap 15.7) must produce
   **no** mirror; deleting the allowlist check must make a test fail.
5. **Version comparison.** Installed `8.14.1-150600.4.40.1` vs mirrored fixed
   `8.14.1-150600.4.51.1` → fixable; reuses the rpm comparer, no new comparer
   (D9). One table row pins it.
6. **Disclosure renders.** A renderer test asserts `CrossMappedFrom` appears in
   the table/JSON/`--explain` output; deleting the render must go red.
7. **Mutation round** after implementation, per the standard discipline
   (commit first; re-run the table after any later change; diff the tree after
   each revert).

## Measurements to run first (first tasks of the implementation plan)

Per the provider's measurement-before-implementation discipline (every `foldKey`
comment cites archive counts). These need the live 445 MB `csaf-vex.tar.bz2`;
delegatable (Sonnet, data-measurement shape).

- **M1 — Leap release census.** Enumerate every distinct `openSUSE Leap X.Y`
  product name the archive publishes natively → the mirror allowlist. Confirm the
  expected set {15.0–15.6, 16.0} and record it with a revisit trigger.
- **M2 — restored-tuple count.** Rebuild (or simulate) with D108 and count the
  `(package, CVE)` tuples the gap-fill mirror restores for `openSUSE Leap:15.6`
  (and the total across all Leap keys). Drives the `leap156` floor re-band and a
  DB-size estimate.
- **M3 — transitional frequency.** Count documents carrying *both* a native Leap
  entry and an SLE-SP{n}/16.x entry for the same package (the gap-fill edge where
  native wins). Expected rare — the D91 census (11,955 same-doc bare+LTSS pairs)
  is the template; record the number so the union deferral is justified with data.
- **M4 — DB-size delta.** The mirrored entries' cost against the current ~1.07 GB.

## Follow-ups after landing

- **Re-band `leap156`'s floor.** PR #130 set `minFindings` to an interim 4
  (aging-out). After D108 restores coverage, re-measure and re-raise the floor to
  the new stable count with headroom, in a chore commit citing D108.
- **`docs/deferred-decisions.md`.** Record the union deferral (with M3's number)
  and the remediation-availability nuance (LTSS-channel fix version), plus the
  allowlist revisit trigger.
- **Roadmap + `docs/DESIGN.md`.** Mark D108; update the SUSE lines. Bilingual
  (`.ko.md`) in the same commit per the docs discipline.

## Risks and non-goals

- **Remediation availability.** The mirrored fix version is the SLE (often LTSS)
  build; a free Leap user may not pull it directly. Disclosed via
  `CrossMappedFrom`; the finding itself is true. Same class of nuance D91 already
  accepted for post-EOL SP6 LTSS fixes on the SLES key.
- **Phantom keys.** Avoided by the allowlist (M1). Never emit a Leap key for a
  release that never existed.
- **Leap-only packages.** Packages Leap ships that are not from SLE are simply
  absent from SLE data, so the mirror never fabricates an entry for them.
- **Not a lifecycle/EOL detector.** D108 does not try to detect that a scanned
  distro is EOL or annotate it as such; it only stops shared-codestream findings
  from disappearing. An EOL-awareness feature is out of scope.
- **Not a general cross-distro alias.** Scoped to the Leap↔SLE binary-build
  relationship, which is a documented, measurable fact. It is not a precedent for
  mapping unrelated ecosystems.
