package source

import (
	"bytes"
	"debug/buildinfo"
	"fmt"
	"io"
	"os"
	"strings"
)

// Classify decides what one target argument names (D22).
//
// Before this, an existing path meant an SBOM, so `assay scan ./bin/assay`
// handed a binary to the CycloneDX parser and reported a malformed document —
// sending the reader after a broken file rather than a misread target.
//
// A bare path is now decided by CONTENT: directory, then Go binary, then
// CycloneDX. Each test is cheap — buildinfo reads a header and fails
// immediately on anything that is not a Go binary, and the CycloneDX test
// reads 512 bytes.
//
// The three are mutually exclusive on any real input, so their order is not
// observable today: a Go binary's header cannot contain `"bomFormat"`, and a
// JSON document cannot satisfy buildinfo. Swapping the last two is a true
// equivalent, verified as a surviving mutation rather than assumed. The order
// is fixed anyway, because the day a fourth format is added the exclusivity
// stops holding and an unordered sniff would change behaviour silently.
//
// A file matching none of them is an error naming all three and the prefixes
// that override them, never a silent fallthrough to whichever branch happens
// to be last — which is what produced "malformed JSON" for a binary.
//
// It returns the kind and the path with any file: / dir: / sbom: prefix
// stripped. The image prefixes are returned INTACT, because Open parses them
// itself and stripping one here would send an oci-dir: layout down the
// registry path.
func Classify(target string) (TargetKind, string, error) {
	// Image schemes first, so an explicit docker-archive: stays reachable.
	if classify(target) != kindRegistry {
		return TargetImage, target, nil
	}
	for _, p := range []struct {
		prefix string
		kind   TargetKind
	}{
		{"sbom:", TargetSBOM},
		{"dir:", TargetDirectory},
		{"file:", TargetGoBinary},
	} {
		if rest, ok := strings.CutPrefix(target, p.prefix); ok {
			return p.kind, rest, nil
		}
	}

	info, err := os.Stat(target)
	if err != nil {
		// Not a path on this machine, so it is a registry reference. A typo'd
		// path reaching the registry loader is the pre-existing behaviour and
		// stays: the alternative is refusing an image whose name happens to
		// look like a path.
		return TargetImage, target, nil
	}
	if info.IsDir() {
		return TargetDirectory, target, nil
	}
	if _, err := buildinfo.ReadFile(target); err == nil {
		return TargetGoBinary, target, nil
	}
	if looksLikeCycloneDX(target) {
		return TargetSBOM, target, nil
	}
	return 0, "", fmt.Errorf(
		"%s is a file, but not a Go binary and not a CycloneDX document; "+
			"prefix it with file:, sbom: or dir: to say which it is", target)
}

// looksLikeCycloneDX reports whether a file opens like a CycloneDX document.
//
// It reads a prefix rather than parsing, and deliberately does not validate:
// the classifier's job is to pick a parser, and the parser it picks reports
// the real errors. Parsing here would read a 40 MB SBOM twice and would make
// a document that is CycloneDX-but-malformed look like "not an SBOM", which
// is a worse message than the one cyclonedx.Parse already gives.
func looksLikeCycloneDX(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var head [512]byte
	n, err := io.ReadFull(f, head[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false
	}
	return bytes.Contains(head[:n], []byte(`"bomFormat"`))
}
