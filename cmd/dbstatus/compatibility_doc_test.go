package main

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// docVersion reads the "Current" cell of the row naming contract in
// docs/compatibility.md (and its Korean pair), whose table starts each row
// with the contract's id in backticks: | `report` | ... | 14 |.
func docVersion(t *testing.T, path, contract string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	re := regexp.MustCompile("(?m)^\\| `" + regexp.QuoteMeta(contract) + "` \\|.*\\| (\\d+) \\|$")
	m := re.FindAllSubmatch(b, -1)
	if len(m) != 1 {
		t.Fatalf("%s: want one row for `%s`, found %d", path, contract, len(m))
	}
	n, _ := strconv.Atoi(string(m[0][1]))
	return n
}

// TestCompatibilityDoc_NamesTheStatusVersion: status.json's row in
// docs/compatibility.md follows statusSchemaVersion.
func TestCompatibilityDoc_NamesTheStatusVersion(t *testing.T) {
	for _, doc := range []string{"../../docs/compatibility.md", "../../docs/compatibility.ko.md"} {
		if got := docVersion(t, doc, "status.json"); got != statusSchemaVersion {
			t.Errorf("%s: status.json schemaVersion %d, code says %d", doc, got, statusSchemaVersion)
		}
	}
}
