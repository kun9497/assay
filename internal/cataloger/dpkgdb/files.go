package dpkgdb

import (
	"bufio"
	"io"
	"strings"
)

// InfoDir is where dpkg keeps one `<package>[:<arch>].list` per installed
// package: the absolute path of every file it installed, one per line
// (D162). A distroless image's status.d carries no such lists.
const InfoDir = "var/lib/dpkg/info"

// ParseFileList reads one `.list` file. Lines are absolute paths; the
// conventional first line `/.` (the root) and blank lines are not files.
func ParseFileList(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line == "/." {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ListOwner reads the package name and architecture a `.list` file's name
// spells: `libc6:amd64.list` is libc6 on amd64, `npm.list` is npm with no
// architecture qualifier (dpkg writes one only for a package installed from a
// Multi-Arch: same lineage). The empty string when base is not a `.list`.
func ListOwner(base string) (name, arch string) {
	stem, ok := strings.CutSuffix(base, ".list")
	if !ok {
		return "", ""
	}
	name, arch, _ = strings.Cut(stem, ":")
	return name, arch
}
