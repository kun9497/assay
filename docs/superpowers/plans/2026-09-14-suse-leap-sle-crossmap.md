# D108 — openSUSE Leap ↔ SLE codestream cross-map — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop openSUSE Leap findings from disappearing as SUSE ages Leap releases out of its CSAF feed, by mirroring the folded SLE codestream advisory onto the corresponding Leap ecosystem key.

**Architecture:** Provider-side (`internal/provider/suse/csaf.go`) fold mirror: after `convert` computes the folded SLE keys (D91 included), emit a mirrored `openSUSE Leap:15.N` affected entry from a `SLES:15.SPN` key, gap-fill (native Leap wins per package). An additive `CrossMappedFrom` field on `advisory.Affected` records the origin; the matcher surfaces it on `Finding` (like `MatchedViaProvides`); every renderer discloses it. No new `Comparer` — Leap and SLES already resolve through the rpm comparer, on the shared 150600 codestream. The scan path stays a pure read (D14).

**Tech Stack:** Go 1.26, standard library only. No new dependency.

**Spec:** `docs/superpowers/specs/2026-09-14-suse-leap-sle-crossmap-design.md` (D108). Read it alongside this plan.

## Global Constraints

- **Go 1.26**; `CGO_ENABLED=0` — no cgo dependency may be introduced (D4). Locally `make test` fails without a C toolchain; run `go test ./...` (CI runs `-race`).
- **No sixth direct dependency** — standard library only for this slice (five-deps rule).
- **Additive fields only; JSON schema stays `10`.** Advisories rebuild from providers on every `db build`, so a new `omitempty` field needs no migration and no schema bump (precedent: `ModuleStream` D80, `Related` D71).
- **No new `Comparer`** (D9). Leap 15.x and SLES:15.SPx share the rpm comparer and the 150600 EVR axis.
- **Scan path makes no network fetch** (D14). This slice only changes `db build` output and match-time surfacing.
- **Commit before running any mutation** against implementation, always (including main-loop `git checkout --` reverts).
- **Escape sequences**: never type a literal escape into a file-generating script; assemble via `chr(92)` and grep the written bytes. (No task here needs one; the guard stands anyway.)
- **Docs are bilingual, EN canonical, `.ko.md` in the same commit** (Task 9).
- **Commit/PR attribution** (append verbatim to every commit and PR):
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_016GTvuYsYEUE9gguoCUCTz4
  ```
  PR descriptions additionally end with the `🤖 Generated with [Claude Code]...` block.

---

## File Structure

- `internal/advisory/advisory.go` — add `Affected.CrossMappedFrom` (storage-side origin marker).
- `internal/provider/suse/csaf.go` — add `leapMirrorKey` (SLE key → Leap key), `leapReleases` allowlist, the mirror pass in `convert`, and two `stats` counters.
- `internal/provider/suse/csaf_test.go` — provider-level convert tests (the observable effect: a mirrored Leap Affected is produced / suppressed).
- `internal/matcher/matcher.go` — add `Finding.CrossMappedFrom`, set it from the matched `aff` at both construction sites.
- `internal/matcher/matcher_test.go` — the end-to-end match test (installed Leap EVR < mirrored SLE fix → fixable finding carrying the origin).
- `internal/report/{table,json,sarif,explain}.go` + their `_test.go` — disclose the origin.
- `.github/scanner-diff-targets.json` — re-raise `leap156`'s interim floor after the DB rebuild (Task 8).
- `docs/DESIGN.md`(+`.ko.md`), the roadmap spec(+`.ko.md`), `docs/deferred-decisions.md`(+`.ko.md`) — record D108 (Task 9).

---

## Task 1: Archive census (M1 allowlist verification, M3 transitional frequency)

Measurement-before-implementation. Delegatable (Sonnet, data-measurement shape). Needs the live 445 MB archive; this box is not sandboxed, so the fetch is allowed. Produces two numbers the later tasks cite; it does **not** block Task 2/3 (the allowlist is lifecycle-grounded in Task 3 and this task confirms it).

**Files:**
- Create: `scratchpad census script` (throwaway, not committed).

**Interfaces:**
- Produces: the confirmed set of native `openSUSE Leap X.Y` releases (expected `{15.0,15.1,15.2,15.3,15.4,15.5,15.6,16.0}`); the count of documents carrying BOTH a native Leap entry and an SLE-SP{n}/16.x entry for the same package (the gap-fill edge, expected rare).

- [ ] **Step 1: Fetch and extract the archive to the scratchpad**

```bash
cd "$SCRATCH"   # the session scratchpad dir
curl -sSfL https://ftp.suse.com/pub/projects/security/csaf-vex.tar.bz2 -o csaf-vex.tar.bz2
mkdir -p csaf && tar -xjf csaf-vex.tar.bz2 -C csaf
ls csaf/csaf-vex | head
```

- [ ] **Step 2: M1 — enumerate native Leap release names**

```python
# census.py — run: python census.py > m1.txt
import json, glob, os
leaps=set()
for f in glob.glob(os.path.join('csaf','csaf-vex','*.json')):
    try: d=json.load(open(f,encoding='utf-8'))
    except Exception: continue
    def walk(bs):
        for b in bs:
            if b.get('category')=='product_name' and b.get('product'):
                n=b['product']['product_id']
                if n.startswith('openSUSE Leap '): leaps.add(n)
            walk(b.get('branches',[]))
    walk(d.get('product_tree',{}).get('branches',[]))
print(sorted(leaps))
```

Expected: only `openSUSE Leap 15.0`..`15.6` and `openSUSE Leap 16.0`. If any other appears (e.g. a future `16.1`), record it — Task 3's `leapReleases` allowlist must list exactly this set.

- [ ] **Step 3: M3 — count transitional documents (native Leap + SLE-SP same package)**

```python
# m3.py — run: python m3.py
import json, glob, os, re
sle=re.compile(r'^SUSE Linux Enterprise Server (\d+)(?: SP(\d+))?(?:-LTSS)?:(.+)$')
leap=re.compile(r'^openSUSE Leap (\d+\.\d+):(.+)$')
def pkgbase(comp):  # strip trailing -EVR to a family name, best-effort
    return re.split(r'-\d', comp, 1)[0]
both=0
for f in glob.glob(os.path.join('csaf','csaf-vex','*.json')):
    try: d=json.load(open(f,encoding='utf-8'))
    except Exception: continue
    leap_pkgs=set(); sle_pkgs=set()
    for v in d.get('vulnerabilities',[]):
        ps=v.get('product_status',{})
        for bucket in ('known_affected','recommended','fixed'):
            for i in ps.get(bucket,[]):
                m=leap.match(i)
                if m: leap_pkgs.add((m.group(1),pkgbase(m.group(2))))
                m=sle.match(i)
                if m: sle_pkgs.add((m.group(1),pkgbase(m.group(3))))
    # a 15.N leap pkg colliding with a 15 SPN sle pkg base
    for (rel,pkg) in leap_pkgs:
        maj,minr=rel.split('.')
        if maj=='15' and (('15' if minr=='0' else '15'),pkg) and any(s[1]==pkg for s in sle_pkgs):
            both+=1; break
print('documents with both native Leap and SLE-same-package:', both)
```

Record the number in Task 9's deferred-decisions entry (justifies the union deferral, D91-census style).

- [ ] **Step 4: Report the two numbers back**

No commit (throwaway scripts). Hand the M1 set and M3 count to Task 3 and Task 9.

---

## Task 2: Add `Affected.CrossMappedFrom`

**Files:**
- Modify: `internal/advisory/advisory.go:46-65` (the `Affected` struct)
- Test: `internal/advisory/advisory_test.go` (create if absent)

**Interfaces:**
- Produces: `advisory.Affected.CrossMappedFrom string` — the ecosystem key an entry was mirrored from (e.g. `"SLES:15.SP6"`), `""` for ordinary entries.

- [ ] **Step 1: Write the failing test (JSON round-trip, omitempty)**

```go
// internal/advisory/advisory_test.go
package advisory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAffected_CrossMappedFrom_RoundTrip(t *testing.T) {
	a := Affected{Ecosystem: "openSUSE Leap:15.6", Name: "curl", CrossMappedFrom: "SLES:15.SP6"}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"cross_mapped_from":"SLES:15.SP6"`) {
		t.Fatalf("field not serialized: %s", b)
	}
	var back Affected
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.CrossMappedFrom != "SLES:15.SP6" {
		t.Fatalf("round-trip lost the field: %q", back.CrossMappedFrom)
	}
}

func TestAffected_CrossMappedFrom_OmitEmpty(t *testing.T) {
	b, _ := json.Marshal(Affected{Ecosystem: "npm", Name: "left-pad"})
	if strings.Contains(string(b), "cross_mapped_from") {
		t.Fatalf("empty field must be omitted: %s", b)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/advisory/ -run TestAffected_CrossMappedFrom -v`
Expected: FAIL — `CrossMappedFrom` undefined.

- [ ] **Step 3: Add the field**

In `internal/advisory/advisory.go`, inside `type Affected struct`, after `ModuleStream`:

```go
	// CrossMappedFrom names the ecosystem key this entry was mirrored from
	// (D108), e.g. "SLES:15.SP6", or "" for an ordinary entry. openSUSE Leap
	// 15.x is built from the SLE 15 SPx binaries on the same 150600
	// codestream with the same EVR numbering, so an SLE codestream advisory
	// answers a Leap query for a shared package; this field discloses that the
	// fixed version named is the SLE (often LTSS-channel) build, which a free
	// Leap user may not obtain directly. Additive like ModuleStream/Related --
	// advisories rebuild from providers on every db build, so no schema bump.
	CrossMappedFrom string `json:"cross_mapped_from,omitempty"`
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/advisory/ -run TestAffected_CrossMappedFrom -v`
Expected: PASS (both).

- [ ] **Step 5: Commit**

```bash
git add internal/advisory/advisory.go internal/advisory/advisory_test.go
git commit -m "$(printf 'feat(advisory): add Affected.CrossMappedFrom for the D108 Leap<->SLE mirror\n\nAdditive, omitempty, no schema bump -- advisories rebuild from providers\neach db build (precedent: ModuleStream D80, Related D71).\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_016GTvuYsYEUE9gguoCUCTz4')"
```

---

## Task 3: The provider mirror pass (`csaf.go`)

The core of D108. Caller-first: the first test asserts the **observable effect** of `convert` — a mirrored Leap `Affected` — then the mirror is implemented, then the tie-break and allowlist branches are pinned.

**Files:**
- Modify: `internal/provider/suse/csaf.go` — add `leapReleases`, `leapMirrorKey`, the mirror pass in `convert` (after the `order` loop that builds `adv.Affected`, before `return adv, true` at ~line 726), and two `stats` counters (`MirroredToLeap`, `SkippedLeapNativeWins`) rendered in `stats.String`.
- Test: `internal/provider/suse/csaf_test.go`

**Interfaces:**
- Consumes: `advisory.Affected.CrossMappedFrom` (Task 2).
- Produces: `leapMirrorKey(sleKey string) (leapKey string, ok bool)` — maps `SLES:15` → `openSUSE Leap:15.0`, `SLES:15.SP{n}` → `openSUSE Leap:15.{n}`, `SLES:16.{m}` → `openSUSE Leap:16.{m}`, and reports `ok=false` for any key whose Leap release is not in `leapReleases`.

- [ ] **Step 1: Write the failing observable-effect test (gap-fill: native absent → mirror fires)**

```go
// internal/provider/suse/csaf_test.go  (add to the existing package suse test file)
func TestConvert_MirrorsSLEOntoLeap_WhenNoNativeLeap(t *testing.T) {
	// One document: SLE 15 SP6-LTSS has a fixed curl; NO openSUSE Leap 15.6
	// entry at all (the aging-out case).
	d := &document{}
	d.Document.Tracking.ID = "CVE-2026-5773"
	d.Document.Title = "curl DoS"
	d.ProductTree.Branches = []branch{
		{Category: "product_name", Product: prod("SUSE Linux Enterprise Server 15 SP6-LTSS")},
		{Category: "product_version", Product: prodPurl(
			"SUSE Linux Enterprise Server 15 SP6-LTSS:curl-8.14.1-150600.4.51.1",
			"pkg:rpm/suse/curl@8.14.1-150600.4.51.1")},
	}
	d.Vulnerabilities = []vuln{}
	d.Vulnerabilities = append(d.Vulnerabilities, mkVuln("CVE-2026-5773",
		nil, []string{"SUSE Linux Enterprise Server 15 SP6-LTSS:curl-8.14.1-150600.4.51.1"}))

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert returned !ok")
	}
	got := findAffected(adv, "openSUSE Leap:15.6", "curl")
	if got == nil {
		t.Fatal("no mirrored openSUSE Leap:15.6 curl entry produced")
	}
	if got.CrossMappedFrom != "SLES:15.SP6" {
		t.Fatalf("CrossMappedFrom = %q, want SLES:15.SP6", got.CrossMappedFrom)
	}
	if !hasFixedRange(got, "8.14.1-150600.4.51.1") {
		t.Fatalf("mirrored entry lost the fixed version: %+v", got.Ranges)
	}
	if st.MirroredToLeap != 1 {
		t.Fatalf("MirroredToLeap = %d, want 1", st.MirroredToLeap)
	}
}
```

> The test relies on small helpers (`prod`, `prodPurl`, `mkVuln`, `vuln`, `findAffected`, `hasFixedRange`). If the existing `csaf_test.go` lacks them, add them in this step — match whatever fixture shape the current tests already use (read the file first) rather than inventing a parallel one. `findAffected` walks `adv.Affected` for a matching `Ecosystem`+`Name`; `hasFixedRange` checks any range has a `Fixed` event equal to the argument.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/provider/suse/ -run TestConvert_MirrorsSLEOntoLeap -v`
Expected: FAIL — no mirrored entry / `MirroredToLeap` undefined.

- [ ] **Step 3: Add `leapReleases` and `leapMirrorKey`**

In `csaf.go`, near `slesKey` (~line 265):

```go
// leapReleases is the set of openSUSE Leap releases the archive actually
// publishes, measured 2026-09-14 (D108 census M1): 15.0-15.6 and 16.0. The
// mirror (leapMirrorKey) emits ONLY to a release in this set, so an SLE
// codestream with no corresponding Leap release -- SLE 15 SP7, whose Leap
// jumped to 16.0 -- never fabricates a phantom "openSUSE Leap:15.7" key
// nothing scans as. This is the same "refuse unknown shapes, never guess"
// discipline foldKey's anchored patterns enforce. Revisit when the census
// shows a new Leap release (e.g. 16.1); a scan-side symptom on a Leap image
// keyed to a release absent here is the trace.
var leapReleases = map[string]bool{
	"openSUSE Leap:15.0": true,
	"openSUSE Leap:15.1": true,
	"openSUSE Leap:15.2": true,
	"openSUSE Leap:15.3": true,
	"openSUSE Leap:15.4": true,
	"openSUSE Leap:15.5": true,
	"openSUSE Leap:15.6": true,
	"openSUSE Leap:16.0": true,
}

// leapMirrorKey maps a folded SLE key to the openSUSE Leap key built from the
// same codestream (D108): SLES:15 -> Leap:15.0 (SP0/GA), SLES:15.SP{n} ->
// Leap:15.{n}, SLES:16.{m} -> Leap:16.{m}. Reports ok=false when the SLE key
// is not a mirrorable Server release, or when the resulting Leap release is
// not one the feed publishes (leapReleases). Leap 15.x is binary-built from
// SLE 15 SPx on the shared 150600 codestream, which is what makes the
// resulting key answer a Leap query for a shared package soundly.
func leapMirrorKey(sleKey string) (string, bool) {
	var leap string
	switch {
	case sleKey == "SLES:15":
		leap = "openSUSE Leap:15.0"
	case strings.HasPrefix(sleKey, "SLES:15.SP"):
		leap = "openSUSE Leap:15." + strings.TrimPrefix(sleKey, "SLES:15.SP")
	case strings.HasPrefix(sleKey, "SLES:16."):
		leap = "openSUSE Leap:16." + strings.TrimPrefix(sleKey, "SLES:16.")
	default:
		return "", false
	}
	if !leapReleases[leap] {
		return "", false
	}
	return leap, true
}
```

- [ ] **Step 4: Add the two stats counters**

In `type stats struct` (csaf.go), near `SkippedLTSSShadowedByMainline`:

```go
	// MirroredToLeap and SkippedLeapNativeWins are D108's mirror pass firing.
	// MirroredToLeap counts affected entries emitted onto an openSUSE Leap key
	// from a folded SLE codestream key (the aging-out gap this slice fills);
	// SkippedLeapNativeWins counts the gap-fill tie-break declining to mirror
	// because the document already carries a native Leap entry for that
	// package. Same per-entry granularity as the Skipped* group above.
	MirroredToLeap        int
	SkippedLeapNativeWins int
```

Add to `stats.String`'s format string and args (append `", %d mirrored onto an openSUSE Leap key from its SLE codestream, %d not mirrored because a native Leap entry already covers the package (D108)"` with `s.MirroredToLeap, s.SkippedLeapNativeWins`).

- [ ] **Step 5: Add the mirror pass in `convert`**

In `convert`, after the `for _, k := range order { ... adv.Affected = append(...) }` loop and before `st.Advisories++` / `return adv, true` (~line 725). It reads the `adv.Affected` just built:

```go
	// D108: mirror each folded SLE codestream entry onto the openSUSE Leap key
	// built from the same 150600 codestream, gap-fill -- only where this
	// document produced no native Leap entry for that package (native wins, so
	// no installed-package finding is ever hidden; the aging-out case has no
	// native entry, so the mirror fills it). See leapMirrorKey/leapReleases.
	native := map[productKey]bool{}
	for i := range adv.Affected {
		a := &adv.Affected[i]
		if strings.HasPrefix(a.Ecosystem, "openSUSE Leap:") {
			native[productKey{eco: a.Ecosystem, pkg: a.Name}] = true
		}
	}
	var mirrors []advisory.Affected
	for i := range adv.Affected {
		a := &adv.Affected[i]
		leap, ok := leapMirrorKey(a.Ecosystem)
		if !ok {
			continue
		}
		if native[productKey{eco: leap, pkg: a.Name}] {
			st.SkippedLeapNativeWins++
			continue
		}
		m := advisory.Affected{
			Ecosystem:       leap,
			Name:            a.Name,
			Ranges:          a.Ranges,
			ModuleStream:    a.ModuleStream,
			CrossMappedFrom: a.Ecosystem,
		}
		mirrors = append(mirrors, m)
		st.MirroredToLeap++
	}
	adv.Affected = append(adv.Affected, mirrors...)
```

> `Ranges` is shared by reference deliberately — the mirror is a read-only alias of the same range slice, never mutated after construction, matching how the store treats every emitted advisory as immutable. If a later change ever mutates ranges post-emit, deep-copy here.

- [ ] **Step 6: Run the observable-effect test — verify it passes**

Run: `go test ./internal/provider/suse/ -run TestConvert_MirrorsSLEOntoLeap -v`
Expected: PASS.

- [ ] **Step 7: Write the tie-break test (native present → no mirror)**

```go
func TestConvert_DoesNotMirror_WhenNativeLeapPresent(t *testing.T) {
	// SLE 15 SP6-LTSS fixed AND a native openSUSE Leap 15.6 known_affected for
	// the same package: native wins, no mirror, finding still present natively.
	d := &document{}
	d.Document.Tracking.ID = "CVE-2026-9999"
	d.ProductTree.Branches = []branch{
		{Category: "product_name", Product: prod("SUSE Linux Enterprise Server 15 SP6-LTSS")},
		{Category: "product_name", Product: prod("openSUSE Leap 15.6")},
		{Category: "product_version", Product: prodPurl(
			"SUSE Linux Enterprise Server 15 SP6-LTSS:curl-8.14.1-150600.4.51.1",
			"pkg:rpm/suse/curl@8.14.1-150600.4.51.1")},
	}
	d.Vulnerabilities = append(d.Vulnerabilities, mkVuln("CVE-2026-9999",
		[]string{"openSUSE Leap 15.6:curl"}, // native known_affected (no fix)
		[]string{"SUSE Linux Enterprise Server 15 SP6-LTSS:curl-8.14.1-150600.4.51.1"}))

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("!ok")
	}
	got := findAffected(adv, "openSUSE Leap:15.6", "curl")
	if got == nil {
		t.Fatal("native Leap finding disappeared") // the user's core requirement
	}
	if got.CrossMappedFrom != "" {
		t.Fatalf("native entry must not be marked cross-mapped: %q", got.CrossMappedFrom)
	}
	if st.MirroredToLeap != 0 || st.SkippedLeapNativeWins != 1 {
		t.Fatalf("tie-break wrong: mirrored=%d nativeWins=%d", st.MirroredToLeap, st.SkippedLeapNativeWins)
	}
}
```

- [ ] **Step 8: Write the allowlist-guard test (SP7 → no phantom Leap 15.7)**

```go
func TestConvert_DoesNotMirror_SP7_NoLeap157(t *testing.T) {
	d := &document{}
	d.Document.Tracking.ID = "CVE-2026-8888"
	d.ProductTree.Branches = []branch{
		{Category: "product_name", Product: prod("SUSE Linux Enterprise Server 15 SP7")},
		{Category: "product_version", Product: prodPurl(
			"SUSE Linux Enterprise Server 15 SP7:curl-8.14.1-150700.7.23.1",
			"pkg:rpm/suse/curl@8.14.1-150700.7.23.1")},
	}
	d.Vulnerabilities = append(d.Vulnerabilities, mkVuln("CVE-2026-8888",
		nil, []string{"SUSE Linux Enterprise Server 15 SP7:curl-8.14.1-150700.7.23.1"}))

	var st stats
	adv, _ := convert(d, &st)
	if findAffected(adv, "openSUSE Leap:15.7", "curl") != nil {
		t.Fatal("mirrored to a phantom openSUSE Leap:15.7 key")
	}
	if st.MirroredToLeap != 0 {
		t.Fatalf("MirroredToLeap = %d, want 0", st.MirroredToLeap)
	}
}
```

- [ ] **Step 9: Run all three provider tests — verify pass**

Run: `go test ./internal/provider/suse/ -run "TestConvert_MirrorsSLEOntoLeap|TestConvert_DoesNotMirror" -v`
Expected: PASS (all three).

- [ ] **Step 10: Add a `leapMirrorKey` unit table (mapping correctness)**

```go
func TestLeapMirrorKey(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"SLES:15", "openSUSE Leap:15.0", true},
		{"SLES:15.SP6", "openSUSE Leap:15.6", true},
		{"SLES:16.0", "openSUSE Leap:16.0", true},
		{"SLES:15.SP7", "", false}, // no Leap 15.7
		{"SLES:12.SP5", "", false}, // no Leap 12.x
		{"openSUSE Leap:15.6", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := leapMirrorKey(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("leapMirrorKey(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
```

Run: `go test ./internal/provider/suse/ -run TestLeapMirrorKey -v` → PASS.

- [ ] **Step 11: Mutation check — delete the mirror emit, confirm red**

Comment out the `adv.Affected = append(adv.Affected, mirrors...)` line. Run the Step 9 tests: `TestConvert_MirrorsSLEOntoLeap` MUST fail. Restore the line (via re-typing, not `git checkout` — the field/counters are uncommitted). Re-run: PASS.

- [ ] **Step 12: Commit**

```bash
git add internal/provider/suse/csaf.go internal/provider/suse/csaf_test.go
git commit -m "$(printf 'feat(suse): D108 mirror SLE codestream advisories onto openSUSE Leap\n\nGap-fill: emit an openSUSE Leap:15.N entry from a folded SLES:15.SPN key\nonly when the document has no native Leap entry for the package, so an\ninstalled-package finding never disappears as SUSE ages Leap out of the\nCSAF feed. Allowlist (census M1) refuses phantom keys like Leap 15.7.\nReuses the rpm comparer on the shared 150600 codestream (no new Comparer).\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_016GTvuYsYEUE9gguoCUCTz4')"
```

---

## Task 4: Surface the origin on `Finding`

**Files:**
- Modify: `internal/matcher/matcher.go` — add `Finding.CrossMappedFrom`; set it at the two construction sites (~`:1009` append, ~`:1025` winner-swap) from the matched `aff`.
- Test: `internal/matcher/matcher_test.go`

**Interfaces:**
- Consumes: `advisory.Affected.CrossMappedFrom` (Task 2), and the mirrored advisories Task 3 produces.
- Produces: `matcher.Finding.CrossMappedFrom string` — the origin of the matched entry, `""` for ordinary matches.

- [ ] **Step 1: Write the failing end-to-end match test**

```go
// internal/matcher/matcher_test.go
func TestMatch_CrossMappedLeapFinding_IsFixableAndDisclosed(t *testing.T) {
	// A mirrored advisory: openSUSE Leap:15.6 curl, fixed at the SLE SP6 EVR,
	// CrossMappedFrom set. An installed Leap curl below that EVR must match and
	// the finding must carry the origin.
	adv := advisory.Advisory{
		ID: "SUSE-CVE-2026-5773", Database: "SUSE", Source: "suse",
		Kind: advisory.KindVulnerability, Aliases: []string{"CVE-2026-5773"},
		Affected: []advisory.Affected{{
			Ecosystem: "openSUSE Leap:15.6", Name: "curl",
			CrossMappedFrom: "SLES:15.SP6",
			Ranges: []advisory.Range{{Type: advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "8.14.1-150600.4.51.1"}}}},
		}},
	}
	// Build the fake store + a Leap 15.6 target with curl 8.14.1-150600.4.40.1,
	// following whatever constructor the existing matcher tests use.
	res := runMatchLeapCurl(t, adv, "8.14.1-150600.4.40.1")
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.CrossMappedFrom != "SLES:15.SP6" {
		t.Fatalf("CrossMappedFrom = %q, want SLES:15.SP6", f.CrossMappedFrom)
	}
}
```

> `runMatchLeapCurl` is a thin helper over the fake `Store` + `Match` the existing tests already use (read `matcher_test.go` for the established pattern — do not invent a new harness). It builds a target whose `Distro.Ecosystem()` is `openSUSE Leap:15.6` with one installed `curl` at the given version and returns `Match`'s result.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/matcher/ -run TestMatch_CrossMappedLeapFinding -v`
Expected: FAIL — `f.CrossMappedFrom` undefined.

- [ ] **Step 3: Add the `Finding` field**

In `type Finding struct` (matcher.go), after `MatchedViaProvides`:

```go
	// CrossMappedFrom is the ecosystem key the matched advisory entry was
	// mirrored from (D108), e.g. "SLES:15.SP6", or "" for an ordinary match.
	// A matcher fact like MatchedName: it is read off the matched Affected at
	// match time so a renderer can disclose that a Leap finding's fixed
	// version is the SLE codestream build. Match is the only constructor that
	// sets it; the zero value ("") is correct for every non-mirrored finding.
	CrossMappedFrom string
```

- [ ] **Step 4: Set it at both construction sites**

In the `Finding{...}` literal (~line 1009) add:

```go
								CrossMappedFrom:    aff.CrossMappedFrom,
```

In the winner-swap block (~line 1025), after `f.MatchedName = lookupName` / `f.MatchedViaProvides = ...`:

```go
							f.CrossMappedFrom = aff.CrossMappedFrom
```

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/matcher/ -run TestMatch_CrossMappedLeapFinding -v`
Expected: PASS.

- [ ] **Step 6: Mutation check — delete the append-site assignment, confirm red**

Remove the `CrossMappedFrom: aff.CrossMappedFrom,` line from the literal. Re-run Step 5: MUST fail. Re-type it. PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/matcher/matcher.go internal/matcher/matcher_test.go
git commit -m "$(printf 'feat(matcher): surface Affected.CrossMappedFrom on Finding (D108)\n\nA matcher fact set from the matched entry at both construction sites, like\nMatchedName/MatchedViaProvides, so renderers can disclose that a Leap\nfinding fixed version is the SLE codestream build.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_016GTvuYsYEUE9gguoCUCTz4')"
```

---

## Task 5: Disclose the origin in every renderer

The "every renderer, not just the table" obligation. One deliverable (disclosure is uniform), four call sites, each with its own test. Read each renderer first for its existing ecosystem/source wording and match the register.

**Files:**
- Modify + Test: `internal/report/table.go`(+`_test.go`), `json.go`(+`_test.go`), `sarif.go`(+`_test.go`), `explain.go`(+`_test.go`).

**Interfaces:**
- Consumes: `matcher.Finding.CrossMappedFrom` (Task 4).

- [ ] **Step 1: JSON — failing test**

```go
// internal/report/json_test.go
func TestJSON_DisclosesCrossMappedFrom(t *testing.T) {
	out := renderJSONOneFinding(t, findingWithCrossMap("SLES:15.SP6"))
	if !strings.Contains(out, `"cross_mapped_from": "SLES:15.SP6"`) &&
		!strings.Contains(out, `"cross_mapped_from":"SLES:15.SP6"`) {
		t.Fatalf("json did not disclose the cross-map origin:\n%s", out)
	}
}
```

> `findingWithCrossMap` and `renderJSONOneFinding` follow the existing json_test helpers. The finding's package ecosystem is `openSUSE Leap:15.6`, matched name `curl`, `CrossMappedFrom` set.

- [ ] **Step 2: JSON — run fail, implement, run pass**

Add a `CrossMappedFrom string \`json:"cross_mapped_from,omitempty"\`` field to the JSON finding DTO in `json.go` and set it from `f.CrossMappedFrom`. Run: `go test ./internal/report/ -run TestJSON_DisclosesCrossMappedFrom -v` → PASS.

- [ ] **Step 3: `--explain` — failing test**

```go
func TestExplain_DisclosesCrossMappedFrom(t *testing.T) {
	out := renderExplain(t, findingWithCrossMap("SLES:15.SP6"))
	if !strings.Contains(out, "SLES:15.SP6") || !strings.Contains(strings.ToLower(out), "codestream") {
		t.Fatalf("--explain did not disclose the SLE codestream origin:\n%s", out)
	}
}
```

- [ ] **Step 4: `--explain` — implement**

In `explain.go`, where the finding's ecosystem/source is explained, add a line when `f.CrossMappedFrom != ""`, e.g.:
`fmt.Fprintf(w, "  cross-mapped from %s: openSUSE Leap shares the %s codestream, so the fixed version shown is the SLE (LTSS-channel) build (D108)\n", f.CrossMappedFrom, "150600")` — match explain.go's existing indentation/format. (Keep the literal "codestream" the test asserts.) Run → PASS.

- [ ] **Step 5: SARIF — failing test + implement**

```go
func TestSARIF_DisclosesCrossMappedFrom(t *testing.T) {
	out := renderSARIF(t, findingWithCrossMap("SLES:15.SP6"))
	if !strings.Contains(out, "SLES:15.SP6") {
		t.Fatalf("sarif did not disclose the cross-map origin:\n%s", out)
	}
}
```

Add the origin to the result's message or a property bag (`properties.crossMappedFrom`) in `sarif.go`, matching how it already carries fix state / source. Run → PASS.

- [ ] **Step 6: Table — failing test + implement**

```go
func TestTable_DisclosesCrossMappedFrom(t *testing.T) {
	out := renderTable(t, findingWithCrossMap("SLES:15.SP6"))
	if !strings.Contains(out, "SLES:15.SP6") {
		t.Fatalf("table did not disclose the cross-map origin:\n%s", out)
	}
}
```

The table is width-sensitive; prefer a marker in the existing ecosystem/fix cell or a footnote line rather than a new column. Match table.go's current cell composition (and keep piped output byte-identical to itself — colors are TTY-only, D107). Run → PASS.

- [ ] **Step 7: Mutation check — per renderer**

For each of the four, remove the disclosure line and confirm that renderer's test goes red, then restore. All four must be genuinely covered.

- [ ] **Step 8: Commit**

```bash
git add internal/report/
git commit -m "$(printf 'feat(report): disclose CrossMappedFrom in every renderer (D108)\n\ntable, json, sarif and --explain each show that a Leap finding fixed\nversion is the SLE codestream (LTSS-channel) build -- the per-renderer\ndisclosure obligation, not just the table.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_016GTvuYsYEUE9gguoCUCTz4')"
```

---

## Task 6: Full suite, vet, build, and the delete-each-call-site sweep

**Files:** none (verification only).

- [ ] **Step 1: Full test suite**

Run: `go test ./...`
Expected: PASS (no C toolchain locally, so no `-race`; CI runs `-race`).

- [ ] **Step 2: Vet and build**

Run: `go vet ./...` then `go build ./...`
Expected: both clean.

- [ ] **Step 3: Deliberate coverage sweep (CLAUDE.md rule)**

Delete — one at a time, re-typing after — each new CALL site and confirm the suite goes red:
1. the mirror `append` in `convert` (Task 3 Step 5) → provider tests red;
2. the `CrossMappedFrom: aff.CrossMappedFrom` literal line (Task 4) → matcher test red;
3. each renderer's disclosure line (Task 5) → that renderer's test red.
If any stays green, the feature is not covered — add the missing assertion before proceeding.

- [ ] **Step 4: Commit (only if the sweep required test fixes)**

```bash
git add -A
git commit -m "test: close D108 coverage gaps found by the delete-call-site sweep

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016GTvuYsYEUE9gguoCUCTz4"
```

---

## Task 7: Open the feature PR

**Files:** none.

- [ ] **Step 1: Push and open the PR**

```bash
git push -u origin <feature-branch>
"C:/Program Files/GitHub CLI/gh.exe" pr create --title "feat: D108 openSUSE Leap <-> SLE codestream cross-map" --body "<summary: problem (leap156 aging out), approach (provider fold mirror, gap-fill, CrossMappedFrom disclosure), tests, census numbers M1/M3, follow-ups (floor re-band Task 8, docs Task 9)>"
```

Body ends with the `🤖 Generated with [Claude Code]` block + session URL. Do not self-merge (policy blocks it); hand the green PR to the user.

---

## Task 8: Rebuild the DB, verify leap156 restored, re-raise its floor (M2/M4)

Depends on the feature PR being merged (or a local `db build` off the feature branch). Delegatable measurement + a chore commit.

**Files:**
- Modify: `.github/scanner-diff-targets.json` (leap156 `minFindings`).

- [ ] **Step 1: Build a database off the D108 build path**

Run `assay db build` (with the SUSE provider) into a scratch DB, or wait for the nightly artifact after merge.

- [ ] **Step 2: M2/M4 — measure restored coverage and DB delta**

Scan `opensuse/leap:15.6` (the pinned ref in the targets file) and count findings; confirm the four curl/libcurl4 tuples (CVE-2026-5773, CVE-2026-7168) return, each carrying `cross_mapped_from`. Record the new leap156 count and the DB size delta vs the pre-D108 build.

- [ ] **Step 3: Re-raise the leap156 floor**

Set `leap156.minFindings` from the interim `4` (PR #130) to the new stable measured count with the house downward headroom (~50% of measured, as debian12/ubuntu2204 carry). Verify offline: `./bin/scandiff -targets .github/scanner-diff-targets.json -offline <capture-dir>` re-judges leap156 green.

- [ ] **Step 4: Commit + PR (chore)**

```bash
git commit -m "$(printf 'chore: re-raise leap156 floor after D108 restored Leap 15.6 coverage\n\nD108 mirrors the SLE 15 SP6 codestream onto openSUSE Leap:15.6; leap156\nnow measures <N> findings (was 8 pre-D108, floor interim-lowered to 4 in\n#130). minFindings -> <M> with the house downward headroom.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_016GTvuYsYEUE9gguoCUCTz4')"
```

---

## Task 9: Documentation (bilingual, same commit) + plan deletion

**Files:**
- Modify: `docs/DESIGN.md` + `docs/DESIGN.ko.md` (roadmap checkbox / SUSE lines, D108).
- Modify: the roadmap spec `docs/superpowers/specs/2026-07-29-assay-roadmap.md` (+`.ko.md`) — D108 decision entry.
- Modify: `docs/deferred-decisions.md` + `.ko.md` — the union deferral (with M3's number), the remediation-availability nuance (LTSS-channel fix version), the allowlist revisit trigger.
- Delete: `docs/superpowers/plans/2026-09-14-suse-leap-sle-crossmap.md` (this plan, once the slice has merged).

- [ ] **Step 1: Write the D108 roadmap decision + DESIGN.md entry (EN)**

Add D108 to the roadmap with its reasoning (aging-out problem, Leap=SLE binary build, gap-fill, disclosure, allowlist). Tick/append the DESIGN.md SUSE line. Cite the census numbers.

- [ ] **Step 2: Add the deferred-decisions entry (EN)**

Record: the union deferral with M3's transitional count (D91-census style), the remediation nuance (mirrored fix is the SLE/LTSS build a free Leap user may not pull; disclosed via `cross_mapped_from`), and the `leapReleases` allowlist revisit trigger.

- [ ] **Step 3: Translate all touched docs to `.ko.md` (delegatable, Sonnet)**

Keep identifiers/keys/flags in English; translate prose. Same commit as the EN change.

- [ ] **Step 4: Delete this plan; commit everything**

```bash
git rm docs/superpowers/plans/2026-09-14-suse-leap-sle-crossmap.md
git add docs/
git commit -m "$(printf 'docs: record D108 (Leap<->SLE cross-map), bilingual; drop the plan\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_016GTvuYsYEUE9gguoCUCTz4')"
```

---

## Self-review notes

- **Spec coverage:** approach A (Task 3), gap-fill merge policy (Task 3 Steps 5/7), `CrossMappedFrom` disclosure (Tasks 2/4/5), allowlist/phantom-key guard (Task 3 Steps 3/8/10), no new Comparer (Task 4 uses rpm via the existing match path), measurements M1/M3 (Task 1) and M2/M4 (Task 8), floor re-band (Task 8), docs incl. union deferral + remediation nuance (Task 9). All spec sections map to a task.
- **Type consistency:** `leapMirrorKey(string) (string, bool)`, `leapReleases map[string]bool`, `stats.MirroredToLeap`/`SkippedLeapNativeWins`, `advisory.Affected.CrossMappedFrom`, `matcher.Finding.CrossMappedFrom` — used identically across Tasks 2–5.
- **Fixture helpers** (`prod`, `prodPurl`, `mkVuln`, `findAffected`, `hasFixedRange`, `runMatchLeapCurl`, `findingWithCrossMap`, renderers' helpers) are explicitly flagged to be reconciled with the existing test files rather than assumed — the one place the executor must read before writing.
