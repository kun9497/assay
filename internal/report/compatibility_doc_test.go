package report

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/kun9497/assay/internal/store"
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

// TestCompatibilityDoc_NamesTheCurrentVersions holds docs/compatibility.md to
// the constants it documents, so a schema bump that forgets the page (and so
// its compatibility note) fails here rather than in a customer's parser.
func TestCompatibilityDoc_NamesTheCurrentVersions(t *testing.T) {
	for _, doc := range []string{"../../docs/compatibility.md", "../../docs/compatibility.ko.md"} {
		if got := docVersion(t, doc, "report"); got != schemaVersion {
			t.Errorf("%s: report schemaVersion %d, code says %d", doc, got, schemaVersion)
		}
		if got := docVersion(t, doc, "database"); got != store.SchemaVersion {
			t.Errorf("%s: database schema %d, code says %d", doc, got, store.SchemaVersion)
		}
	}
}
