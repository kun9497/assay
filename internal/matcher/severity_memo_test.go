package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/severity"
)

// TestMemoHighest_HitEqualsMiss holds the memo's one obligation: a cached
// answer must be indistinguishable from a computed one. The poisoning
// mutation this guards against is a hit path returning a stale or wrong
// band — behavior the full suite cannot see when its fixtures never repeat
// a vector set within one Match.
func TestMemoHighest_HitEqualsMiss(t *testing.T) {
	memo := make(map[string]sevScore)
	vecs := []string{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
	b1, s1, _ := memoHighest(memo, vecs)
	b2, s2, _ := memoHighest(memo, vecs) // second call is the cache hit
	wb, ws := severity.Highest(vecs)
	if b1 != wb || s1 != ws || b2 != wb || s2 != ws {
		t.Fatalf("memoHighest = (%v,%v) then (%v,%v), want (%v,%v) both times", b1, s1, b2, s2, wb, ws)
	}
	if len(memo) != 1 {
		t.Fatalf("memo holds %d entries, want 1", len(memo))
	}
}

// TestMemoHighest_SeparatorBypassesCache holds the aliasing guard: a vector
// containing the join separator must never enter the cache, because two
// DIFFERENT vector lists could share its joined key.
func TestMemoHighest_SeparatorBypassesCache(t *testing.T) {
	memo := make(map[string]sevScore)
	memoHighest(memo, []string{"garbage|with|separator"})
	if len(memo) != 0 {
		t.Fatalf("memo holds %d entries after a separator-carrying vector, want 0 (bypass)", len(memo))
	}
	memoHighest(memo, []string{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "also|bad"})
	if len(memo) != 0 {
		t.Fatalf("memo holds %d entries, want 0 — any separator in the LIST bypasses", len(memo))
	}
}

// D156: a cache hit answers with the same v2 origin as the miss that filled
// it, so the second finding scored from one vector set is not shown as banded
// by v3 when it was banded by v2.
func TestMemoHighest_CacheHitKeepsTheV2Origin(t *testing.T) {
	memo := map[string]sevScore{}
	vecs := []string{"AV:N/AC:L/Au:N/C:P/I:P/A:P"}
	_, _, first := memoHighest(memo, vecs)
	_, _, second := memoHighest(memo, vecs)
	if !first || !second {
		t.Errorf("fromV2 = %v then %v, want true both times", first, second)
	}
}
