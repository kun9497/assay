package knvd

import (
	"strings"
	"testing"
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
