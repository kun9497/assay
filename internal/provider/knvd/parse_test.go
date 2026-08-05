package knvd

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// One notice, several CVEs: each gets its own record pointing back at the
// same notice, because the join is on the CVE and a reader following any of
// them wants the same page.
func TestConvert_OneRecordPerNamedCVE(t *testing.T) {
	got := convert(rawNotice{
		ID:    "6a7164a72677c331e44a17f8",
		Title: "Rails 제품 보안 업데이트 권고",
		ContentText: "□ 개요 o Rails에서 발생하는 취약점을 해결한 보안 업데이트 발표 " +
			"□ 설명 o Insecure Default Initialization 취약점(CVE-2026-66066) " +
			"o 두 번째 취약점(CVE-2026-70001)",
	})
	if len(got) != 2 {
		t.Fatalf("convert produced %d record(s), want one per CVE: %+v", len(got), got)
	}
	seen := map[string]bool{}
	for _, e := range got {
		seen[e.CVE] = true
		if e.Source != SourceName {
			t.Errorf("Source = %q, want %q", e.Source, SourceName)
		}
		if e.Title != "Rails 제품 보안 업데이트 권고" {
			t.Errorf("Title = %q, want the notice's own headline", e.Title)
		}
		// The link must be the notice's page, built from its id. The list
		// response's own `url` field is an external reference and is often
		// null, so it is not what a reader should be sent to.
		if want := detailURL + "6a7164a72677c331e44a17f8"; e.URL != want {
			t.Errorf("URL = %q, want %q", e.URL, want)
		}
	}
	for _, want := range []string{"CVE-2026-66066", "CVE-2026-70001"} {
		if !seen[want] {
			t.Errorf("%s missing from %+v", want, got)
		}
	}
	// Determinism is a global constraint, not just "the right set came
	// back" -- a caller writing records in whatever order convert returns
	// them needs that order to be reproducible across runs. Checking
	// membership through `seen` above cannot catch a reversed or
	// unsorted result, so pin the order explicitly.
	if got[0].CVE != "CVE-2026-66066" || got[1].CVE != "CVE-2026-70001" {
		t.Errorf("got order [%s, %s], want ascending sorted order [CVE-2026-66066, CVE-2026-70001]",
			got[0].CVE, got[1].CVE)
	}
}

// The same CVE named twice in one notice yields one record, not two. The
// store would collapse them anyway, but emitting duplicates makes the
// provenance count lie about how much was written.
func TestConvert_DeduplicatesWithinANotice(t *testing.T) {
	got := convert(rawNotice{
		ID:          "abc",
		Title:       "제목",
		ContentText: "CVE-2026-1 설명 CVE-2026-1 다시 CVE-2026-1",
	})
	if len(got) != 1 {
		t.Errorf("convert produced %d record(s), want 1: %+v", len(got), got)
	}
}

// A notice naming no CVE produces nothing. Enrichment is a CVE join, so a
// record with no key could never be read back.
func TestConvert_ANoticeWithNoCVEProducesNothing(t *testing.T) {
	if got := convert(rawNotice{ID: "abc", Title: "제목", ContentText: "CVE 없는 안내문"}); len(got) != 0 {
		t.Errorf("convert produced %+v, want nothing", got)
	}
}

// The summary is the overview section when there is one, so a reader gets
// the point rather than the whole notice. KISA marks it "□ 개요" and ends it
// at the next "□ " heading.
func TestConvert_SummaryIsTheOverviewSection(t *testing.T) {
	got := convert(rawNotice{
		ID:    "abc",
		Title: "제목",
		ContentText: "□ 개요 o 업데이트 발표 " +
			"□ 설명 o 자세한 내용 CVE-2026-1 " +
			"□ 해결 방안 o 최신 버전으로 갱신",
	})
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	if !strings.Contains(got[0].Summary, "업데이트 발표") {
		t.Errorf("Summary = %q, want the 개요 section", got[0].Summary)
	}
	if strings.Contains(got[0].Summary, "최신 버전으로 갱신") {
		t.Errorf("Summary = %q, want it to stop at the next heading", got[0].Summary)
	}
}

// A notice with no 개요 heading still yields a usable summary rather than an
// empty one -- the corpus is not uniform, and an empty field renders as a
// finding that gained nothing.
func TestConvert_FallsBackWhenThereIsNoOverviewHeading(t *testing.T) {
	got := convert(rawNotice{ID: "abc", Title: "제목", ContentText: "CVE-2026-1 에 대한 안내입니다"})
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	if got[0].Summary == "" {
		t.Error("Summary is empty for a notice with no 개요 heading")
	}
}

// A notice with "□ 개요" but no closing "□ " heading (malformed, or the
// content was itself cut off upstream) must not hand back an unbounded
// summary -- the same display-length bound applies as when there is no
// 개요 heading at all, because both are "the section's end is unknown."
func TestConvert_OverviewSectionIsBoundedWhenThereIsNoClosingHeading(t *testing.T) {
	long := strings.Repeat("나", 400) // no second "□ " heading follows this
	got := convert(rawNotice{
		ID:          "abc",
		Title:       "제목",
		ContentText: "□ 개요 " + long + " CVE-2026-1",
	})
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	if n := utf8.RuneCountInString(got[0].Summary); n > fallbackSummaryLimit {
		t.Errorf("Summary has %d runes, want at most %d (the same bound the no-heading fallback uses)",
			n, fallbackSummaryLimit)
	}
}

// The fallback summary must be cut on a rune boundary, not a byte offset --
// this text is Korean, and a byte slice can land inside a multi-byte
// syllable and emit replacement characters. Every other fixture's fallback
// text is well under the limit, so this one alone exercises the truncating
// branch.
//
// The leading "X" matters, not just padding: "가" is a 3-byte rune, and
// fallbackSummaryLimit (300) is a multiple of 3, so byte-slicing 400 bare
// "가" runes at byte offset 300 lands on a rune boundary by coincidence --
// wrong rune count, but still valid UTF-8, so it would not exercise
// utf8.ValidString at all. Shifting everything by one byte forces a
// byte-offset cut to land inside a multi-byte syllable instead.
func TestConvert_FallbackSummaryIsTruncatedOnARuneBoundary(t *testing.T) {
	long := "X" + strings.Repeat("가", 400) // 401 runes, well over fallbackSummaryLimit
	got := convert(rawNotice{ID: "abc", Title: "제목", ContentText: long + " CVE-2026-1"})
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	summary := got[0].Summary
	if !utf8.ValidString(summary) {
		t.Errorf("Summary is not valid UTF-8: %q", summary)
	}
	if n := utf8.RuneCountInString(summary); n != fallbackSummaryLimit {
		t.Errorf("Summary has %d runes, want exactly %d", n, fallbackSummaryLimit)
	}
}
