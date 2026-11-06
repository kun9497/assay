package redhat

import (
	"testing"
	"time"
)

// ageDays rounds UP and never goes negative: the printed age must exhibit
// the violation the refusal announces (review of QA 2026-11-06), and a
// clock behind the archive's date is a zero-day-old archive.
func TestAgeDays(t *testing.T) {
	for _, c := range []struct {
		age  time.Duration
		want int
	}{
		{-72 * time.Hour, 0},
		{0, 0},
		{time.Second, 1},
		{24 * time.Hour, 1},
		{24*time.Hour + time.Second, 2},
		{maxArchiveAge, 21},
		{maxArchiveAge + time.Second, 22},
	} {
		if got := ageDays(c.age); got != c.want {
			t.Errorf("ageDays(%v) = %d, want %d", c.age, got, c.want)
		}
	}
}
