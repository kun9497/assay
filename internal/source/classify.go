package source

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
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
// reads a 512-byte prefix before falling back to a streaming scan for the
// top-level key.
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
// It deliberately does not validate: the classifier's job is to pick a parser,
// and the parser it picks reports the real errors. Deciding "not an SBOM" for
// a document that is CycloneDX-but-malformed would be a worse message than the
// one cyclonedx.Parse already gives.
//
// Two passes. The cheap one looks for the marker in the first 512 bytes, which
// is where every SBOM this project has seen puts it. The fallback exists
// because JSON member order is arbitrary: a document leading with a large
// `metadata` block is perfectly legal and pushes `bomFormat` past any fixed
// prefix — an 880-byte CycloneDX 1.6 file from a real generator did exactly
// that and was rejected outright. Before target sniffing existed, every file
// went to the order-independent parser, so a fixed prefix was a regression for
// valid input.
//
// The fallback walks top-level keys with a streaming decoder rather than
// unmarshalling, and stops at the first one that matches, so it reads no more
// of a 40 MB SBOM than it has to.
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
	if bytes.Contains(head[:n], []byte(`"bomFormat"`)) {
		return true
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false
	}
	return hasTopLevelKey(f, "bomFormat")
}

// hasTopLevelKey reports whether a JSON object has the given key at depth 1.
//
// Depth matters: a `components[].properties[].name` of "bomFormat" would
// otherwise classify an arbitrary document as an SBOM, and CycloneDX property
// names are attacker-controlled in the sense that they come from whatever tool
// produced the file.
func hasTopLevelKey(r io.Reader, key string) bool {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return false
	}
	depth := 1
	// Token() yields a key and then its value, with no marker between them, so
	// key position has to be tracked. Without this, {"note":"bomFormat"} would
	// match on the VALUE and classify an arbitrary document as an SBOM.
	expectKey := true
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case json.Delim:
			if t == '{' || t == '[' {
				depth++
			} else {
				depth--
				if depth == 0 {
					return false
				}
			}
			// A nested value has just ended, so the next token at depth 1 is
			// a key again.
			expectKey = depth == 1
		default:
			if depth != 1 {
				continue
			}
			if expectKey {
				if s, ok := t.(string); ok && s == key {
					return true
				}
				expectKey = false
				continue
			}
			// That was the value; the next depth-1 token is a key.
			expectKey = true
		}
	}
}
