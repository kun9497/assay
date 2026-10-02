package source

import (
	"archive/zip"
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
// A bare path is now decided by CONTENT: directory, then Go binary, then jar,
// then an SBOM (CycloneDX or SPDX, D84). Each test is cheap — buildinfo reads
// a header and fails immediately on anything that is not a Go binary,
// looksLikeJar reads four magic bytes before opening the central directory,
// and each SBOM test reads a 512-byte prefix before falling back to a
// streaming scan for its own top-level key.
//
// The five are mutually exclusive on any real input, so their order is not
// observable today: a Go binary's header cannot contain `"bomFormat"`,
// `"spdxVersion"`, or the zip magic, a JSON document cannot satisfy
// buildinfo or start with zip magic bytes, and CycloneDX's and SPDX's own
// marker keys cannot both appear as top-level keys of one well-formed
// document of either shape. Swapping sniffs among themselves is a true
// equivalent, verified as a surviving mutation rather than assumed for the
// original three — and D84's own addition, landing a fifth without
// disturbing that, is the case the day-it-happens caution below was written
// for. The order is fixed anyway: were a sixth format ever added on top,
// exclusivity might not hold for IT, and an unordered sniff would change
// behaviour silently.
//
// This only decides "some kind of SBOM" for the CycloneDX/SPDX pair —
// scancmd's own TargetSBOM branch re-sniffs a resolved file's content by the
// exported LooksLikeSPDX (the same fileHasTopLevelKey test this runs) to pick
// the parser, the same way it already had to open the file itself to read it.
//
// A file matching none of them is an error naming all five and the prefixes
// that override them, never a silent fallthrough to whichever branch happens
// to be last — which is what produced "malformed JSON" for a binary. The one
// exception is a file the SBOM sniffs stopped reading at D112's per-file
// limit before they could tell: that error is the limit's, in the words an
// image's file and a decoded SBOM get, because the file may well be an SBOM
// and no prefix would get it scanned — sbom: reaches decodeSBOM's refusal of
// the same file.
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
		{"jar:", TargetJar},
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
	if looksLikeJar(target) {
		return TargetJar, target, nil
	}
	isCycloneDX, cdxHitLimit := fileHasTopLevelKey(target, "bomFormat")
	if isCycloneDX {
		return TargetSBOM, target, nil
	}
	isSPDX, spdxHitLimit := fileHasTopLevelKey(target, "spdxVersion")
	if isSPDX {
		return TargetSBOM, target, nil
	}
	// Neither marker found, and a sniff that stopped at D112's per-file limit
	// could not have found one: the error is the limit's. When neither finds
	// its marker the two walks read the same tokens and stop at the same one,
	// so the flags agree and either alone would do — dropping one from this
	// condition is a surviving mutation for that reason, verified. Both are
	// read so the error does not rest on that argument.
	if cdxHitLimit || spdxHitLimit {
		return 0, "", FileLimitError(target)
	}
	return 0, "", fmt.Errorf(
		"%s is a file, but not a Go binary, not a CycloneDX document, not an SPDX document, "+
			"and not a jar; prefix it with file:, sbom:, dir: or jar: to say which it is", target)
}

// jarMagic is the four bytes every ZIP-format file begins with, "PK\x03\x04" —
// spelled as hex bytes rather than typed as an escape sequence, per
// CLAUDE.md's "writing escape sequences into files": a literal \x03\x04 typed
// into a source file risks losing a backslash in transit and becoming the
// byte it was meant to denote, and a []byte literal is the one place in this
// codebase that value needs writing at all.
var jarMagic = []byte{0x50, 0x4b, 0x03, 0x04}

// looksLikeJar reports whether target looks like a Java archive (D70): ZIP
// magic, AND either a .jar/.war name or a META-INF/ entry inside it.
//
// Neither signal alone is enough. The name alone would misclassify an
// ordinary .zip that happens to be named "release.jar" by something that is
// not a Java archive at all; magic bytes alone would misclassify any plain
// .zip (an SBOM bundle, a source archive) as a component inventory, since
// jar and war are themselves just the ZIP format with different intended
// contents. META-INF/ is the one thing every real jar carries — at minimum
// a MANIFEST.MF — that a plain zip does not.
func looksLikeJar(target string) bool {
	f, err := os.Open(target)
	if err != nil {
		return false
	}
	defer f.Close()

	var head [4]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return false
	}
	if !bytes.Equal(head[:], jarMagic) {
		return false
	}

	lower := strings.ToLower(target)
	if strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war") {
		return true
	}

	// The name did not settle it — open the central directory and look for a
	// META-INF/ entry. zip.OpenReader re-reads the file from the start (it
	// does not reuse f, which has already consumed 4 bytes), which is fine:
	// this path is only reached for a file that already passed the magic-byte
	// check above, so the extra open is not paid by every random file on the
	// classifier's most common (non-jar) inputs.
	zr, err := zip.OpenReader(target)
	if err != nil {
		return false
	}
	defer zr.Close()
	for _, e := range zr.File {
		if strings.HasPrefix(e.Name, "META-INF/") {
			return true
		}
	}
	return false
}

// fileHasTopLevelKey reports whether a file opens like the SBOM its key marks —
// "bomFormat" for CycloneDX, "spdxVersion" for SPDX (D84) — and, when it does
// not, whether that is because the sniff stopped at D112's per-file limit
// before it could tell (sniffTopLevelKey). Both SBOM sniffs are this one
// function, so the bound cannot be on one of them and not the other.
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
// of a 40 MB SBOM than it has to — and never more of any file than D112's
// per-file limit (sniffTopLevelKey).
func fileHasTopLevelKey(path, key string) (found, hitLimit bool) {
	f, err := os.Open(path)
	if err != nil {
		return false, false
	}
	defer f.Close()
	return sniffTopLevelKey(f, key)
}

// LooksLikeSPDX reports whether a file opens like an SPDX JSON document —
// exported, unlike the CycloneDX sniff, because scancmd's own TargetSBOM
// branch re-sniffs a resolved file's content by this same test to choose
// between the two SBOM parsers (D84): Classify only decides "this is some
// kind of SBOM", not which one, so the choice has to be made again at the
// point the file is actually opened for parsing.
//
// Same two-pass strategy as the CycloneDX sniff, for the identical reason:
// JSON member order is arbitrary, so "spdxVersion" is no more guaranteed to
// sit near the front of the document than "bomFormat" was.
//
// It drops hitLimit: decodeSBOM, its one caller, reads the file under the same
// limit and names an over-limit file itself, whichever parser this picks.
func LooksLikeSPDX(path string) bool {
	found, _ := fileHasTopLevelKey(path, "spdxVersion")
	return found
}

// sniffTopLevelKey is the two passes: the quoted key in the first 512 bytes,
// else a streaming walk of the top-level keys.
//
// Everything it reads comes through one LimitedReader of MaxFileBytes+1
// (D112). The sniff is a read of the target as much as the decode after it
// is, and on a bare path it runs first, before decodeSBOM's bound applies —
// so without a bound of its own it was the one read of an uploaded SBOM
// D112's per-file limit did not reach. A walk that never finds its key reads
// to the end of the document, and json.Decoder buffers a string token whole,
// so one multi-gigabyte string ahead of the key was held in memory entire
// before the sniff could say no. Bounded, it pulls at most limit+1 bytes, the
// same reach decodeSBOM has — every document the decoder would accept is one
// the sniff sees to its end — and a key past that is not found.
//
// hitLimit says the walk ended because that reader ran dry, all limit+1 bytes
// served, rather than because the document itself said no. Classify turns it
// into the limit's own error instead of "not a CycloneDX document", which
// would be wrong about a file that may well be one. The +1 is what tells the
// two apart, as in readEntry: a document of exactly the limit leaves one byte
// unserved and is judged on its content; one byte more drains the reader.
//
// The head is replayed in front of the rest rather than re-read after a Seek,
// so the bytes the fast path took count against the same limit as everything
// after them.
func sniffTopLevelKey(r io.Reader, key string) (found, hitLimit bool) {
	lr := &io.LimitedReader{R: r, N: MaxFileBytes + 1}
	var head [512]byte
	n, err := io.ReadFull(lr, head[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false, false
	}
	if bytes.Contains(head[:n], []byte(`"`+key+`"`)) {
		return true, false
	}
	if hasTopLevelKey(io.MultiReader(bytes.NewReader(head[:n]), lr), key) {
		return true, false
	}
	return false, lr.N == 0
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
