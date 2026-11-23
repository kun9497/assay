package dbcmd

import (
	"fmt"
	"io"

	"github.com/kun9497/assay/internal/store"
)

// Verify is `assay db verify` (D173): 0 when every entry is what the build
// recorded, 2 when it is not or the database records nothing to compare.
func Verify(dbPath string, stdout, stderr io.Writer) int {
	db, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	defer db.Close()
	n, err := db.Verify()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		fmt.Fprintln(stderr, "run `assay db update` to download it again, or `assay db build` to build it from source")
		return 2
	}
	if _, err := fmt.Fprintf(stdout, "%s: %d entries verified\n", dbPath, n); err != nil {
		return 2
	}
	return 0
}
