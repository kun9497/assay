package pacmandb

import (
	"io"
	"strings"
)

// ParseFiles reads a package's `files` file, the sibling of its `desc` under
// /var/lib/pacman/local/<name>-<version>/ (D162): the `%FILES%` section lists
// every installed path relative to the root, directories with a trailing
// slash. Directories are not files and are left out; a `%BACKUP%` section,
// when present, is not read.
func ParseFiles(r io.Reader) ([]string, error) {
	fields, err := parseSections(r)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range fields["FILES"] {
		if f == "" || strings.HasSuffix(f, "/") {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}
