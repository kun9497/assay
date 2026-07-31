package osv

// Alpine ecosystems are release-qualified (D6) and the published
// ecosystems.txt does not list them — it carries the bare "Alpine" and no
// versioned key at all. The bucket's JSON listing is where they appear, so
// db update discovers them rather than carrying a hardcoded list that would
// silently stop covering releases published after this build.

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

const alpineListingURL = "https://storage.googleapis.com/storage/v1/b/" +
	"osv-vulnerabilities/o?delimiter=/&prefix=Alpine&fields=prefixes"

func AlpineEcosystems(ctx context.Context, c *http.Client) ([]string, error) {
	return alpineEcosystemsFrom(ctx, c, alpineListingURL)
}

func alpineEcosystemsFrom(ctx context.Context, c *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list Alpine ecosystems: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list Alpine ecosystems: %s", resp.Status)
	}

	var listing struct {
		Prefixes []string `json:"prefixes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		return nil, fmt.Errorf("decode Alpine ecosystem listing: %w", err)
	}
	// An empty (or absent) "prefixes" field means the listing shape changed or
	// the bucket moved — the request itself came back well-formed but hollow.
	// Checked on the RAW listing, before filtering: a listing that legitimately
	// contains only the unversioned "Alpine/" prefix is a real, if narrow,
	// response (nothing to fetch, nothing broken), and must not be conflated
	// with a broken listing that never had any prefixes at all.
	if len(listing.Prefixes) == 0 {
		return nil, fmt.Errorf("Alpine ecosystem listing yielded no releases: %s", url)
	}

	var out []string
	for _, p := range listing.Prefixes {
		eco := strings.TrimSuffix(p, "/")
		// The bare "Alpine" prefix has no release. An advisory stored under it
		// could never match a release-qualified package (D6), so ingesting it
		// would add records no lookup ever reaches.
		if _, rel, ok := strings.Cut(eco, ":"); !ok || rel == "" {
			continue
		}
		out = append(out, eco)
	}

	// Sort by release, not lexically: "Alpine:v3.2" sorts ABOVE "Alpine:v3.19"
	// as a string, and db status would print a list that looks corrupted.
	slices.SortFunc(out, func(a, b string) int {
		return cmpRelease(a, b)
	})
	return out, nil
}

// cmpRelease orders "Alpine:vX.Y" by X then Y. Anything unparseable sorts last
// rather than panicking: a new key shape should be visible, not fatal.
func cmpRelease(a, b string) int {
	amaj, amin, aok := releaseParts(a)
	bmaj, bmin, bok := releaseParts(b)
	switch {
	case !aok && !bok:
		return strings.Compare(a, b)
	case !aok:
		return 1
	case !bok:
		return -1
	}
	if amaj != bmaj {
		return cmp.Compare(amaj, bmaj)
	}
	return cmp.Compare(amin, bmin)
}

func releaseParts(eco string) (major, minor int, ok bool) {
	_, rel, found := strings.Cut(eco, ":v")
	if !found {
		return 0, 0, false
	}
	majStr, minStr, found := strings.Cut(rel, ".")
	if !found {
		return 0, 0, false
	}
	major, err := strconv.Atoi(majStr)
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(minStr)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}
