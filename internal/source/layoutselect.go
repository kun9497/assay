package source

import (
	"fmt"
	"os"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const refNameAnnotation = "org.opencontainers.image.ref.name"

// layoutSelector splits "path@which" from an oci-dir: target. which names one
// entry of the layout's index.json by its ref name or its digest. A path that
// exists as written is a path, "@" and all.
func layoutSelector(s string) (path, which string) {
	i := strings.LastIndex(s, "@")
	if i <= 0 || i == len(s)-1 {
		return s, ""
	}
	if _, err := os.Stat(s); err == nil {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// selectedIndex is a layout's index holding only the entry a selector named.
type selectedIndex struct {
	indexReader
	m *v1.IndexManifest
}

func (s selectedIndex) IndexManifest() (*v1.IndexManifest, error) { return s.m, nil }

// selectFromLayout narrows a layout to the one entry which names.
func selectFromLayout(idx indexReader, path, which string) (indexReader, error) {
	m, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read oci layout %s: %w", path, err)
	}
	var found []v1.Descriptor
	digests := map[v1.Hash]bool{}
	for _, d := range m.Manifests {
		if (d.Digest.String() == which || d.Annotations[refNameAnnotation] == which) && !digests[d.Digest] {
			digests[d.Digest] = true
			found = append(found, d)
		}
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("oci layout %s has no entry named %q; it holds %s", path, which, layoutEntries(m.Manifests))
	case 1:
	default:
		return nil, fmt.Errorf("oci layout %s names %d different entries %q; select one by digest: %s",
			path, len(found), which, layoutEntries(found))
	}
	one := *m
	one.Manifests = found
	return selectedIndex{indexReader: idx, m: &one}, nil
}

func layoutEntries(ds []v1.Descriptor) string {
	var out []string
	for _, d := range ds {
		out = append(out, layoutEntry(d.Annotations[refNameAnnotation], d.Digest))
	}
	return strings.Join(out, ", ")
}

func layoutEntry(refName string, h v1.Hash) string {
	if refName == "" {
		return h.String()
	}
	return refName + " (" + h.String() + ")"
}

// refuseLayoutTie refuses a choice between different images that match the
// platform equally well and sit under different top-level entries of the
// layout: a directory written twice, app:1.0 then app:2.0. The walk order
// picked the first, so the older image could exit 0 while the newer was never
// read (QA 2026-11-20) -- the fallback D119 rules out. Within one entry the
// order is an index's own, and the first is the answer there.
func refuseLayoutTie(cands []candidate, i int, what string) error {
	chosen := cands[i]
	tied := []string{layoutEntry(chosen.refName, chosen.root)}
	seen := map[v1.Hash]bool{chosen.digest: true}
	for _, c := range cands {
		if c.root != chosen.root && !seen[c.digest] && samePlatform(c.plat, chosen.plat) {
			seen[c.digest] = true
			tied = append(tied, layoutEntry(c.refName, c.root))
		}
	}
	if len(tied) == 1 {
		return nil
	}
	return fmt.Errorf("%s holds %d different %s images: %s; name one as %s@<ref name or digest>",
		what, len(tied), PlatformString(chosen.plat), strings.Join(tied, ", "), what)
}
