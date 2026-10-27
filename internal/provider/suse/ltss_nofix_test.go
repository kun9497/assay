package suse

import (
	"strings"
	"testing"
)

// D149: after SLES 15 SP6 left general support, SUSE's documents keep the
// EOL'd product in known_affected (no fix) beside the SP6-LTSS recommended
// fix. D91's tie-break dropped the LTSS entry because a mainline entry
// existed, so an LTSS image with the fix installed scanned "affected, no fix
// available" -- 167 such shapes in the 400 most recent documents (2026-10-22
// audit A5, php8 8.2.35-150600.3.39.1 the measured case). A mainline entry
// with no fix now yields to the LTSS fix: one fixed range, no "affected at
// every version" range beside it, which would still match the fixed build.
func TestConvert_D149_LTSSFixReplacesMainlineNoFix(t *testing.T) {
	d := buildDoc(t, "CVE-2026-0149",
		[]string{"SUSE Linux Enterprise Server 15 SP6", "SUSE Linux Enterprise Server 15 SP6-LTSS"},
		map[string]string{
			"php8":                      "pkg:rpm/suse/php8@?upstream=php8.src.rpm",
			"php8-8.2.35-150600.3.39.1": "pkg:rpm/suse/php8@8.2.35-150600.3.39.1?upstream=php8-8.2.35-150600.3.39.1.src.rpm",
		},
		[]string{"SUSE Linux Enterprise Server 15 SP6-LTSS:php8-8.2.35-150600.3.39.1"},
		[]string{"SUSE Linux Enterprise Server 15 SP6:php8"}, nil)

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped the document")
	}
	a := affectedByName(adv)["SLES:15.SP6/php8"]
	if len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 2 || a.Ranges[0].Events[1].Fixed != "8.2.35-150600.3.39.1" {
		t.Fatalf("php8 ranges = %+v, want exactly one: introduced 0, fixed 8.2.35-150600.3.39.1", a.Ranges)
	}
	if st.LTSSFixReplacedMainlineNoFix != 1 || st.SkippedLTSSShadowedByMainline != 0 {
		t.Errorf("LTSSFixReplacedMainlineNoFix = %d, SkippedLTSSShadowedByMainline = %d, want 1 and 0",
			st.LTSSFixReplacedMainlineNoFix, st.SkippedLTSSShadowedByMainline)
	}
	if st.Unfixable != 0 || st.UnfixableUnstated != 0 {
		t.Errorf("Unfixable = %d (unstated %d), want 0: the no-fix entry was replaced, not emitted",
			st.Unfixable, st.UnfixableUnstated)
	}
}

// The mainline no-fix entry's stated reason (no_fix_planned on the EOL'd
// product) goes with it, as D128's Leap replacement does, and is counted so
// a run that drops one says so.
func TestConvert_D149_ReplacedNoFixWithAReasonIsCounted(t *testing.T) {
	d := buildDoc(t, "CVE-2026-0150",
		[]string{"SUSE Linux Enterprise Server 15 SP6", "SUSE Linux Enterprise Server 15 SP6-LTSS"},
		map[string]string{
			"php8":                      "pkg:rpm/suse/php8@?upstream=php8.src.rpm",
			"php8-8.2.35-150600.3.39.1": "pkg:rpm/suse/php8@8.2.35-150600.3.39.1?upstream=php8-8.2.35-150600.3.39.1.src.rpm",
		},
		[]string{"SUSE Linux Enterprise Server 15 SP6-LTSS:php8-8.2.35-150600.3.39.1"},
		[]string{"SUSE Linux Enterprise Server 15 SP6:php8"},
		[]map[string]any{{"category": "no_fix_planned", "product_ids": []string{"SUSE Linux Enterprise Server 15 SP6:php8"}}})

	var st stats
	adv, _ := convert(d, &st)
	a := affectedByName(adv)["SLES:15.SP6/php8"]
	if len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 2 || a.Ranges[0].Events[1].Fixed != "8.2.35-150600.3.39.1" {
		t.Fatalf("php8 ranges = %+v, want the one LTSS fixed range", a.Ranges)
	}
	if st.LTSSFixReplacedWithReason != 1 || st.UnfixableWontFix != 0 {
		t.Errorf("LTSSFixReplacedWithReason = %d, UnfixableWontFix = %d, want 1 and 0",
			st.LTSSFixReplacedWithReason, st.UnfixableWontFix)
	}
}

// Unchanged by D149: an LTSS entry with no fix of its own replaces nothing
// (both sides say "affected"), and a mainline fix still shadows an LTSS fix
// (TestConvert_LTSSShadowedByMainlineSameDocument).
func TestConvert_D149_LTSSNoFixStillShadowed(t *testing.T) {
	d := buildDoc(t, "CVE-2026-0151",
		[]string{"SUSE Linux Enterprise Server 15 SP6", "SUSE Linux Enterprise Server 15 SP6-LTSS"},
		map[string]string{"php8": "pkg:rpm/suse/php8@?upstream=php8.src.rpm"},
		nil,
		[]string{"SUSE Linux Enterprise Server 15 SP6:php8", "SUSE Linux Enterprise Server 15 SP6-LTSS:php8"}, nil)

	var st stats
	adv, _ := convert(d, &st)
	a := affectedByName(adv)["SLES:15.SP6/php8"]
	if len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 1 {
		t.Fatalf("php8 ranges = %+v, want the one no-fix range", a.Ranges)
	}
	if st.LTSSFixReplacedMainlineNoFix != 0 || st.SkippedLTSSShadowedByMainline != 1 {
		t.Errorf("LTSSFixReplacedMainlineNoFix = %d, SkippedLTSSShadowedByMainline = %d, want 0 and 1",
			st.LTSSFixReplacedMainlineNoFix, st.SkippedLTSSShadowedByMainline)
	}
}

// The progress line names the replacement, so a sync's log shows it at work.
func TestStatsString_ReportsD149(t *testing.T) {
	got := stats{LTSSFixReplacedMainlineNoFix: 167, LTSSFixReplacedWithReason: 4}.String()
	want := "167 mainline no-fix entries given their LTSS twin's fix (D149, 4 of them with a stated fix-state reason dropped)"
	if !strings.Contains(got, want) {
		t.Errorf("stats.String() = %q, want it to contain %q", got, want)
	}
}

// A mainline recommended entry with no version to compare says "affected"
// as much as a known_affected does (store's fallback), so it yields to an
// LTSS fix the same way. And an LTSS recommended entry with no version is
// no fix to give: it is shadowed, not counted as a replacement.
func TestConvert_D149_OnlyARealVersionCountsAsAFix(t *testing.T) {
	sp6, ltss := "SUSE Linux Enterprise Server 15 SP6", "SUSE Linux Enterprise Server 15 SP6-LTSS"
	t.Run("mainline recommended with no version yields", func(t *testing.T) {
		d := buildDoc(t, "CVE-2026-0152", []string{sp6, ltss},
			map[string]string{
				"php8":                      "pkg:rpm/suse/php8@?upstream=php8.src.rpm",
				"php8-8.2.35-150600.3.39.1": "pkg:rpm/suse/php8@8.2.35-150600.3.39.1?upstream=php8-8.2.35-150600.3.39.1.src.rpm",
			},
			[]string{sp6 + ":php8", ltss + ":php8-8.2.35-150600.3.39.1"}, nil, nil)
		var st stats
		adv, _ := convert(d, &st)
		a := affectedByName(adv)["SLES:15.SP6/php8"]
		if len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 2 || st.LTSSFixReplacedMainlineNoFix != 1 {
			t.Errorf("ranges %+v, replaced %d; want the LTSS fix alone and 1", a.Ranges, st.LTSSFixReplacedMainlineNoFix)
		}
	})
	t.Run("LTSS recommended with no version is shadowed", func(t *testing.T) {
		d := buildDoc(t, "CVE-2026-0153", []string{sp6, ltss},
			map[string]string{"php8": "pkg:rpm/suse/php8@?upstream=php8.src.rpm"},
			[]string{ltss + ":php8"}, []string{sp6 + ":php8"}, nil)
		var st stats
		adv, _ := convert(d, &st)
		a := affectedByName(adv)["SLES:15.SP6/php8"]
		if len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 1 || st.LTSSFixReplacedMainlineNoFix != 0 || st.SkippedLTSSShadowedByMainline != 1 {
			t.Errorf("ranges %+v, replaced %d, shadowed %d; want the no-fix range, 0 and 1",
				a.Ranges, st.LTSSFixReplacedMainlineNoFix, st.SkippedLTSSShadowedByMainline)
		}
	})
}

// An SLE known_not_affected entry is never stored (D125 reads that bucket
// for Leap keys only), so it does not compete with an LTSS fix: the fix is
// kept, as it was before D149, with nothing shadowed or replaced.
// vunnel's CSAF parser instead lets a plain "not affected" outrank the LTSS
// fix; this test records that assay does not, rather than leaving it
// implicit.
func TestConvert_D149_SLENotAffectedDoesNotCompete(t *testing.T) {
	sp6, ltss := "SUSE Linux Enterprise Server 15 SP6", "SUSE Linux Enterprise Server 15 SP6-LTSS"
	d := buildDocWith(t, "CVE-2026-0154", []string{sp6, ltss},
		map[string]string{
			"php8":                      "pkg:rpm/suse/php8@?upstream=php8.src.rpm",
			"php8-8.2.35-150600.3.39.1": "pkg:rpm/suse/php8@8.2.35-150600.3.39.1?upstream=php8-8.2.35-150600.3.39.1.src.rpm",
		},
		[]string{ltss + ":php8-8.2.35-150600.3.39.1"}, nil, []string{sp6 + ":php8"}, nil)
	var st stats
	adv, _ := convert(d, &st)
	a := affectedByName(adv)["SLES:15.SP6/php8"]
	if len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 2 || st.LTSSFixReplacedMainlineNoFix != 0 || st.SkippedLTSSShadowedByMainline != 0 {
		t.Errorf("ranges %+v, replaced %d, shadowed %d; want the LTSS fix alone, 0 and 0",
			a.Ranges, st.LTSSFixReplacedMainlineNoFix, st.SkippedLTSSShadowedByMainline)
	}
}
