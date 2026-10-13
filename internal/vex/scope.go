package vex

import (
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// Target is what the scan scanned, as far as a statement's scope can see it
// (D121). The zero value is "not an image": every image-scoped statement is
// then skipped, which is the rule for an SBOM, a directory or a binary scan.
type Target struct {
	// Image is true for an image scan, whatever the loader.
	Image bool
	// Repository is the typed registry reference's repository as
	// go-containerregistry normalises it ("index.docker.io/library/alpine"),
	// or "" when the image was not named by a registry reference — a
	// docker-archive: tarball or an oci-dir: layout, whose name is whatever
	// the file is called. Such an image can be matched by digest only.
	Repository string
	// Tag is the typed reference's tag, the implied "latest" included, since
	// that is the tag that was pulled. "" when the reference named a digest.
	Tag string
	// Digests are the manifest digest scanned and, when one was resolved,
	// the index it was listed in (D119's ImageRecord). Either identifies the
	// image; a digest the reference was typed with is always one of them.
	Digests []string
	// UbuntuCodename is os-release VERSION_CODENAME on an Ubuntu target, ""
	// otherwise. Canonical's OpenVEX writes distro=<codename> (distro=jammy)
	// where syft writes distro=ubuntu-22.04, so an Ubuntu package answers to
	// both spellings.
	UbuntuCodename string
}

// imageRef is one image product of a statement, reduced to what can be
// compared against a Target. Exactly one of the three shapes applies:
//
//   - digest set: matches a target holding that manifest or index digest,
//     whatever either name says — a digest is the image's content, and a
//     repository name is only where it was found.
//   - tag set (with repository): matches a registry target of that
//     repository typed with that tag.
//   - repository only: matches a registry target of that repository at any
//     tag or digest — the version-less reading every package product
//     already gets (D104).
//
// A product that names an image but none of those — a pkg:oci purl with no
// digest and no repository_url — is still an image product, so it still
// scopes its statement, and it matches no target. When in doubt the
// statement is skipped, never applied.
type imageRef struct {
	repository string
	tag        string
	digest     string
}

func (r imageRef) matches(t Target) bool {
	if !t.Image {
		return false
	}
	if r.digest != "" {
		for _, d := range t.Digests {
			if d != "" && strings.EqualFold(d, r.digest) {
				return true
			}
		}
		return false
	}
	if r.repository == "" || t.Repository == "" || r.repository != t.Repository {
		return false
	}
	if r.tag != "" {
		return r.tag == t.Tag
	}
	return true
}

// imageFromPURL reads a pkg:docker or pkg:oci product. ok is false for any
// other purl type, which is a package product.
//
// pkg:docker/<namespace>/<name>@<tag or digest>?repository_url=<host>: the
// registry defaults to Docker Hub (the purl spec's default), and a namespace-
// less name is an official image (pkg:docker/alpine is docker.io/library/
// alpine), both through go-containerregistry's own normalisation so they
// compare equal to a typed "alpine:3.19".
//
// pkg:oci/<name>@<digest>?repository_url=<full repository>&tag=<tag>: the
// purl spec makes the version a digest and repository_url the whole
// repository path. Without repository_url the name alone does not say which
// registry, so only the digest can identify the image.
//
// Other qualifiers (arch, platform, os) are not compared: a digest already
// fixes the platform, and a tag names one index for every platform.
func imageFromPURL(p pkgmeta.PURL) (imageRef, bool) {
	switch p.Type {
	case "docker":
		var r imageRef
		host := registryHost(p.Qualifiers["repository_url"])
		if host == "" {
			host = name.DefaultRegistry
		}
		path := p.Name
		if p.Namespace != "" {
			path = p.Namespace + "/" + p.Name
		}
		r.repository = normalizeRepository(host + "/" + path)
		if isDigest(p.Version) {
			r.digest = p.Version
		} else {
			r.tag = p.Version
		}
		return r, true
	case "oci":
		var r imageRef
		if repo := p.Qualifiers["repository_url"]; repo != "" {
			r.repository = normalizeRepository(stripScheme(repo))
		}
		if isDigest(p.Version) {
			r.digest = p.Version
		} else if p.Version != "" {
			// Not the spec's shape, but a tag here is the only reading it
			// has; it can match only with a repository_url beside it.
			r.tag = p.Version
		}
		if r.digest == "" && r.tag == "" {
			r.tag = p.Qualifiers["tag"]
		}
		return r, true
	}
	return imageRef{}, false
}

// imageFromReference reads a product @id that is not a purl as an image
// reference, when it is shaped like one: "ghcr.io/org/app:1.2",
// "alpine:3.19", "registry.example.com/team/app@sha256:…". It must carry a
// "/", ":" or "@", so a bare word ("nginx", the D104 table's non-purl @id) is
// still an exact-string product rather than docker.io/library/nginx, and it
// must not be some other identifier scheme (a CPE, a URN, a URL).
//
// A reference with no tag is repository-only: go-containerregistry would
// imply "latest", but a document that wrote no tag said nothing about one.
//
// An image named through a transport — "docker://ghcr.io/org/app:1.2", the
// spelling skopeo and the containers tools use — is read as the reference
// after it. One that names a file or a layout ("docker-archive:/srv/app.tar",
// "oci-dir:./layout"), or a transport reference that does not parse, is still
// an image product and identifies nothing: dropping it would unscope its
// statement, so it scopes it to no target instead. The same holds for a
// pkg:docker or pkg:oci purl spelled in a case ParsePURL does not read.
func imageFromReference(s string) (imageRef, bool) {
	lower := strings.ToLower(s)
	for _, tr := range referenceTransports {
		if strings.HasPrefix(lower, tr) {
			if r, ok := imageFromReference(s[len(tr):]); ok {
				return r, true
			}
			return imageRef{}, true
		}
	}
	for _, tr := range fileTransports {
		if strings.HasPrefix(lower, tr) {
			return imageRef{}, true
		}
	}
	if isImagePURLType(s) {
		return imageRef{}, true
	}
	if s == "" || strings.ContainsAny(s, " \t\n") || strings.Contains(s, "://") ||
		!strings.ContainsAny(s, "/:@") {
		return imageRef{}, false
	}
	for _, scheme := range []string{"cpe:", "urn:", "pkg:"} {
		if strings.HasPrefix(lower, scheme) {
			return imageRef{}, false
		}
	}
	if repo, digest, ok := strings.Cut(s, "@"); ok {
		if !isDigest(digest) {
			return imageRef{}, false
		}
		ref, err := name.NewDigest(repo + "@" + digest)
		if err != nil {
			return imageRef{}, false
		}
		return imageRef{repository: ref.Context().Name(), digest: ref.DigestStr()}, true
	}
	last := s[strings.LastIndexByte(s, '/')+1:]
	if strings.Contains(last, ":") {
		tag, err := name.NewTag(s)
		if err != nil {
			return imageRef{}, false
		}
		return imageRef{repository: tag.Context().Name(), tag: tag.TagStr()}, true
	}
	repo, err := name.NewRepository(s)
	if err != nil {
		return imageRef{}, false
	}
	return imageRef{repository: repo.Name()}, true
}

// referenceTransports prefix an image reference; fileTransports name an image
// by a file or directory, which no scan target's digest or name can be
// compared against. Both are lower case, compared case-insensitively.
var (
	referenceTransports = []string{"docker://", "oci://", "docker-daemon:"}
	fileTransports      = []string{"docker-archive:", "oci-archive:", "oci-dir:", "oci:"}
)

// isImagePURLType reports whether s is spelled as a pkg:docker or pkg:oci
// purl, in any case — true even when it does not parse, which is the point:
// an unreadable image product must still scope its statement.
func isImagePURLType(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "pkg:docker/") || strings.HasPrefix(lower, "pkg:oci/")
}

// TargetFromReference builds the registry half of a Target from a reference
// as the user typed it: its normalised repository and its tag ("latest" when
// none was typed, since that is what was pulled). An unparseable reference
// leaves both empty, so only a digest can identify the image.
func TargetFromReference(ref string) (repository, tag string) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", ""
	}
	if t, ok := r.(name.Tag); ok {
		return r.Context().Name(), t.TagStr()
	}
	return r.Context().Name(), ""
}

func normalizeRepository(s string) string {
	repo, err := name.NewRepository(s)
	if err != nil {
		return ""
	}
	return repo.Name()
}

// registryHost turns a docker purl's repository_url into a registry host:
// the scheme and any path dropped, and Docker Hub's web address read as its
// registry, which is how the purl spec's own default is written.
func registryHost(s string) string {
	s = stripScheme(s)
	s, _, _ = strings.Cut(s, "/")
	if s == "hub.docker.com" {
		return name.DefaultRegistry
	}
	return s
}

func stripScheme(s string) string {
	if _, rest, ok := strings.Cut(s, "://"); ok {
		return rest
	}
	return s
}

func isDigest(s string) bool {
	algo, hex, ok := strings.Cut(s, ":")
	return ok && algo != "" && hex != "" && strings.HasPrefix(algo, "sha")
}
