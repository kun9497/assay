// Package tomlblock reads the one TOML shape several lockfiles share: a flat
// sequence of [[package]] tables whose name and version are bare quoted
// scalars.
//
// It is not a TOML parser and does not try to be. Cargo.lock, uv.lock and
// poetry.lock are machine-written in this exact subset, which is why a line
// scanner is honest for them and dishonest for pnpm-lock.yaml (D61): YAML's
// nesting means a restricted reader works on fixtures and quietly mis-reads a
// real file, where here anything outside the subset produces no field rather
// than a wrong one.
//
// It exists as its own package so the catalogers built on it cannot drift.
// Duplicating the scanner would mean a fix to one reader silently not reaching
// the other, and the failure that produces — a package that is not cataloged —
// is a false negative.
package tomlblock

import (
	"bufio"
	"bytes"
	"strings"
)

// Block is one [[package]] table. Either field may be empty: an incomplete
// block is returned rather than dropped, because the caller has to COUNT it.
// A block that vanishes here is indistinguishable from one that was never in
// the file, which breaks the Components == Cataloged + skips invariant every
// cataloger in this repo holds.
type Block struct {
	Name    string
	Version string
}

// Scan returns one Block per [[package]] table, in file order.
func Scan(data []byte) []Block {
	var (
		blocks []Block
		open   bool
		cur    Block
	)

	closeBlock := func() {
		if !open {
			return
		}
		blocks = append(blocks, cur)
		open, cur = false, Block{}
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[[package]]" {
			closeBlock()
			open = true
			continue
		}
		// Any other table header ends the block. Cargo.lock v1 closes with a
		// [metadata] table whose keys name every package again, and uv.lock
		// writes [package.metadata] and [package.dev-dependencies] sub-tables
		// - reading on past either lets a stray assignment complete a block
		// whose own version never arrived.
		if strings.HasPrefix(line, "[") {
			closeBlock()
			continue
		}
		if !open {
			// The lockfile's own preamble: `version = 1`, `requires-python`,
			// and anything else above the first [[package]].
			continue
		}

		// Only the FIRST assignment of each field is taken. Both fields sit at
		// the top of a block, and a later one belongs to something else -
		// uv.lock writes inline tables naming dependencies inside the same
		// block, and letting the last win renames the package to one of them.
		// That name is itself real, so the lookup succeeds and reports another
		// package's advisories.
		if cur.Name == "" {
			if v, ok := stringField(line, "name"); ok {
				cur.Name = v
				continue
			}
		}
		if cur.Version == "" {
			if v, ok := stringField(line, "version"); ok {
				cur.Version = v
			}
		}
	}
	// A scanner error here is a read failure on an in-memory buffer, which
	// cannot happen for the callers - they pass a whole file already read.
	// The last block still has to be closed.
	closeBlock()

	return blocks
}

// stringField matches `key = "value"` and returns the value.
//
// The key is compared exactly rather than by prefix, so a future "name_hint"
// field cannot silently become the name. A value that is not a quoted scalar -
// an inline table, an array, a multi-line string - yields nothing rather than a
// guess: uv.lock writes `source = { registry = "..." }` and `wheels = [`, and
// neither field this reads is ever written that way.
func stringField(line, key string) (string, bool) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", false
	}
	if strings.TrimSpace(line[:eq]) != key {
		return "", false
	}
	v := strings.TrimSpace(line[eq+1:])
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", false
	}
	v = v[1 : len(v)-1]
	if v == "" {
		return "", false
	}
	return v, true
}
