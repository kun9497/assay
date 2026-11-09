package apkdb

import (
	"bufio"
	"io"
	"strings"
)

// ParseFiles reads the file ownership an apk installed database carries
// inline (D162): within a record, each `F:` line names a directory and each
// `R:` line after it a file in that directory. The result maps "dir/file"
// (no leading slash, as apk spells it) to the owning package's name -- the
// `P:` of the record the lines sit in. A record with no `P:` owns nothing;
// an `R:` before any `F:` is a malformed line and is skipped, like any other
// line Parse does not read.
func ParseFiles(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	var name, dir string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			name, dir = "", ""
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || len(key) != 1 {
			continue
		}
		switch key[0] {
		case 'P':
			name = value
		case 'F':
			dir = value
		case 'R':
			if name == "" || dir == "" || value == "" {
				continue
			}
			out[dir+"/"+value] = name
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
