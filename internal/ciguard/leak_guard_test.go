package ciguard

import (
	"regexp"
	"strings"
	"testing"
)

// leakGuard finds what an install step leaves in the calling shell: a
// variable holding a mktemp path, or a trap on EXIT (EXIT in any case, or its
// number 0, alone or among other signals). GitLab runs before_script and
// script in one shell, so either reaches the job's own steps -- the
// four-line form's `trap 'rm -f "$t"' EXIT` deleted a report.txt a later
// step had put in t (main QA of ef0bc1a, 2026-11-13).
//
// It reads the document as sh would rather than as a pattern. Lines ending
// in an unquoted backslash join the next, and a YAML folded scalar (`>`)
// folds; a YAML item or mapping value (`- ...`, `script: ...`, `run: ...`,
// a flow sequence `[a, b]`) is unquoted as YAML does; each line splits into
// commands at ; && || & and | outside quotes, a subshell `( ... )` and a
// comment are skipped, the words that open a body or a condition and the
// builtins that run their arguments in the same shell (`{ then do else ! if
// elif while until time command export readonly local declare typeset`,
// leading NAME=value assignments) come off, `eval`'s argument is read again,
// and the words go through sh's quote removal. Four review rounds of PR #327
// found a regex for this leaking both ways.
//
// It is a lint over this repository's examples, held to what a reader
// rewriting the four-line form would plausibly write, not a shell parser.
// Deliberately not read: a trap in a case arm, a function body defined on
// the line, a heredoc's body (read as commands, so a trap in one is
// refused); a trap or mktemp after a quote-spanning multi-line string. A
// refusal there is loud -- the documents' test goes red -- and a miss is a
// spelling nobody writes in an install step. A trap on TERM or INT alone is a
// job's own business, not the installer's leftover (main QA of 67e2cf6,
// 2026-11-13: `trap 'echo stopping' TERM` in an independent job was refused).
type leakGuard struct{}

// leakedIntoJob is the guard, read over the install jobs only (installJobs).
var leakedIntoJob leakGuard

// mktempValue is an assignment word, after quote removal, whose value is a
// mktemp path: NAME=$(mktemp), NAME=$( mktemp ), NAME=`mktemp`,
// NAME=$(TMPDIR=x mktemp), NAME=$(command mktemp), NAME=${X:-$(mktemp)}. Only
// a word that assigns in the job shell is read: a command's argument -- the
// script of `sh -c '...'`, the text `printf` prints -- is not one (main QA of
// 4d823d1, 2026-11-16: both had been refused from a pattern over the whole
// command).
var mktempValue = regexp.MustCompile("^\\w+=(?:\\$\\{\\w+:?[-=+]\\s*)?(?:\\$\\(\\s*(?:\\w+=\\S*\\s+)*(?:command\\s+)?|`\\s*)mktemp\\b")

// mappingKey is a YAML mapping key with a scalar after it on the same line.
var mappingKey = regexp.MustCompile(`^[A-Za-z_][\w-]*:[ \t]+`)

// assignmentWord is a NAME=value word.
var assignmentWord = regexp.MustCompile(`^\w+=`)

// FindString is the first line of text that leaks, "" when none does.
func (leakGuard) FindString(text string) string {
	for _, line := range logicalLines(text) {
		if lineLeaks(line) {
			return line
		}
	}
	return ""
}

// MatchString reports whether any line of text leaks.
func (g leakGuard) MatchString(text string) bool { return g.FindString(text) != "" }

// logicalLines joins what sh or YAML reads as one line: a line ending in an
// unquoted backslash with the next, and the more-indented lines of a YAML
// folded scalar (a value of `>` or `>-`) into the line that opened it.
func logicalLines(text string) []string {
	raw := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var out []string
	indent := func(s string) int { return len(s) - len(strings.TrimLeft(s, " \t")) }
	for i := 0; i < len(raw); i++ {
		line := raw[i]
		for continues(line) && i+1 < len(raw) {
			i++
			line = line[:len(line)-1] + strings.TrimLeft(raw[i], " \t")
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, ">") || strings.HasSuffix(trimmed, ">-") {
			head := strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(trimmed, "-"), ">"))
			if head == "-" || strings.HasSuffix(head, ":") {
				base := indent(line)
				var folded []string
				for i+1 < len(raw) && strings.TrimSpace(raw[i+1]) != "" && indent(raw[i+1]) > base {
					i++
					folded = append(folded, strings.TrimSpace(raw[i]))
				}
				out = append(out, strings.Repeat(" ", base)+"- "+strings.Join(folded, " "))
				continue
			}
		}
		out = append(out, line)
	}
	return out
}

// continues reports whether a line ends in a backslash that joins the next
// one: unquoted, unescaped, and not inside a comment -- a YAML comment line or
// a shell comment after a command ends at the newline, backslash or not (main
// QA of 4d823d1, 2026-11-16: a `# ... \\` comment had swallowed the real EXIT
// trap on the line after it).
func continues(line string) bool {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "#") {
		return false
	}
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			if i == len(s)-1 {
				return true
			}
			i++
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return false
		}
	}
	return false
}

func lineLeaks(line string) bool {
	s := strings.TrimSpace(line)
	yamlValue := false
	if strings.HasPrefix(s, "- ") || s == "-" {
		s = strings.TrimSpace(strings.TrimPrefix(s, "-"))
		yamlValue = true
	}
	if m := mappingKey.FindString(s); m != "" {
		s = strings.TrimSpace(s[len(m):])
		yamlValue = true
	}
	if !yamlValue {
		return shellLeaks(s)
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		for _, item := range flowItems(s[1 : len(s)-1]) {
			if shellLeaks(yamlUnquote(item)) {
				return true
			}
		}
		return false
	}
	return shellLeaks(yamlUnquote(s))
}

func shellLeaks(s string) bool {
	for _, cmd := range shellCommands(s) {
		if commandLeaks(cmd) {
			return true
		}
	}
	return false
}

// flowItems splits a YAML flow sequence's body at the commas outside quotes.
func flowItems(s string) []string {
	var items []string
	var cur strings.Builder
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '"' && c == '\\' && i+1 < len(s):
			cur.WriteByte(c)
			i++
			c = s[i]
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
		case quote == 0 && c == ',':
			items = append(items, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	return append(items, strings.TrimSpace(cur.String()))
}

// yamlUnquote is a YAML scalar as YAML reads it when it is quoted -- "..."
// with its backslash escapes, '...' with ” for a quote -- a trailing YAML
// comment after the closing quote dropped. Anything else is s.
func yamlUnquote(s string) string {
	if len(s) < 2 || (s[0] != '"' && s[0] != '\'') {
		return s
	}
	q := s[0]
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case q == '"' && c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case q == '\'' && c == '\'' && i+1 < len(s) && s[i+1] == '\'':
			i++
			b.WriteByte('\'')
		case c == q:
			rest := strings.TrimSpace(s[i+1:])
			if rest == "" || strings.HasPrefix(rest, "#") {
				return b.String()
			}
			return s
		default:
			b.WriteByte(c)
		}
	}
	return s
}

// shellCommands splits one line of sh into its simple commands at the
// separators that end one outside quotes. A subshell `( ... )` at a
// command's start is skipped whole, so a separator inside it does not split
// off a command that is then read as the job shell's; a comment, from an
// unquoted # that starts a word, ends the line.
func shellCommands(s string) []string {
	var cmds []string
	var cur strings.Builder
	quote := byte(0)
	depth := 0
	atStart := true
	flush := func() {
		if c := strings.TrimSpace(cur.String()); c != "" {
			cmds = append(cmds, c)
		}
		cur.Reset()
		atStart = true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' && i+1 < len(s) {
				if depth == 0 {
					cur.WriteByte(c)
					cur.WriteByte(s[i+1])
				}
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
		case c == '\\' && i+1 < len(s):
			if depth == 0 {
				cur.WriteByte(c)
				cur.WriteByte(s[i+1])
			}
			i++
			continue
		case c == '\'' || c == '"':
			quote = c
		case depth > 0:
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
			}
			continue
		case c == '(' && atStart:
			depth = 1
			continue
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t' || s[i-1] == ';'):
			flush()
			return cmds
		case c == ';' || c == '&' || c == '|':
			flush()
			continue
		}
		if c != ' ' && c != '\t' {
			atStart = false
		}
		if depth == 0 {
			cur.WriteByte(c)
		}
	}
	flush()
	return cmds
}

// prefixWords are the words that open a body or a condition, or run the rest
// of the command in the same shell.
var prefixWords = map[string]bool{"{": true, "then": true, "do": true, "else": true, "!": true, "if": true, "elif": true,
	"while": true, "until": true, "time": true, "command": true, "export": true, "readonly": true, "local": true, "declare": true, "typeset": true}

// commandLeaks reports whether one simple command leaves a mktemp variable
// or an EXIT trap in the shell that runs it.
func commandLeaks(cmd string) bool {
	words := shellWords(cmd)
	// The words before the command name: body and condition openers,
	// declaration builtins, and NAME=value assignments -- the last the
	// only place a mktemp path is assigned in this shell.
	for len(words) > 0 && (prefixWords[words[0]] || assignmentWord.MatchString(words[0])) {
		if mktempValue.MatchString(words[0]) {
			return true
		}
		words = words[1:]
	}
	if len(words) == 0 {
		return false
	}
	if words[0] == "eval" {
		return shellLeaks(strings.Join(words[1:], " "))
	}
	if words[0] != "trap" {
		return false
	}
	words = words[1:]
	if len(words) > 0 && words[0] == "--" {
		words = words[1:]
	}
	// trap HANDLER SIGNAL...; a handler of "-" resets, and a bare signal
	// list (trap EXIT) resets in POSIX sh too.
	if len(words) < 2 || words[0] == "-" {
		return false
	}
	for _, sig := range words[1:] {
		if strings.EqualFold(sig, "EXIT") || strings.EqualFold(sig, "SIGEXIT") || sig == "0" {
			return true
		}
	}
	return false
}

// shellWords is cmd's words after sh's quote removal: '...' literal, "..."
// with \ escaping " \ $ and `, $'...' as a quoted word, \ outside quotes
// escaping the next byte. A redirection ends a word and takes its target
// with it: EXIT>/dev/null is the word EXIT.
func shellWords(cmd string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	end := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case c == ' ' || c == '\t':
			end()
		case c == '>' || c == '<':
			// A leading fd number (2>) belongs to the redirection.
			if inWord && allDigitsWord(cur.String()) {
				cur.Reset()
				inWord = false
			}
			end()
			for i+1 < len(cmd) && strings.IndexByte("<>&|", cmd[i+1]) >= 0 {
				i++
			}
			for i+1 < len(cmd) && (cmd[i+1] == ' ' || cmd[i+1] == '\t') {
				i++
			}
			for i+1 < len(cmd) && cmd[i+1] != ' ' && cmd[i+1] != '\t' {
				i++
			}
		case c == '\'' || (c == '$' && i+1 < len(cmd) && cmd[i+1] == '\''):
			if c == '$' {
				i++
			}
			inWord = true
			for i++; i < len(cmd) && cmd[i] != '\''; i++ {
				cur.WriteByte(cmd[i])
			}
		case c == '"':
			inWord = true
			for i++; i < len(cmd) && cmd[i] != '"'; i++ {
				if cmd[i] == '\\' && i+1 < len(cmd) && strings.IndexByte("\"\\$`", cmd[i+1]) >= 0 {
					i++
				}
				cur.WriteByte(cmd[i])
			}
		case c == '\\' && i+1 < len(cmd):
			inWord = true
			i++
			cur.WriteByte(cmd[i])
		case (c == '$' && i+1 < len(cmd) && cmd[i+1] == '(') || c == '`':
			// A command substitution is part of the word it appears in,
			// spaces and all: t=$( mktemp ) is one word.
			inWord = true
			j := substitutionEnd(cmd, i)
			cur.WriteString(cmd[i:j])
			i = j - 1
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	end()
	return words
}

// substitutionEnd is the index just past the command substitution starting
// at cmd[i] -- $( ... ) with its nesting, or ` ... ` -- or len(cmd) when it
// does not close on the line.
func substitutionEnd(cmd string, i int) int {
	if cmd[i] == '`' {
		if k := strings.IndexByte(cmd[i+1:], '`'); k >= 0 {
			return i + 1 + k + 1
		}
		return len(cmd)
	}
	depth := 0
	for j := i + 1; j < len(cmd); j++ {
		switch cmd[j] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j + 1
			}
		}
	}
	return len(cmd)
}

func allDigitsWord(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// The review rounds of PR #327, line by line: what a reader adapting the
// four-line form would write, and what is not the job shell's at all. The
// lines are raw strings so the fixtures carry the bytes sh would read.
func TestLeakGuardReadsLinesAsShDoes(t *testing.T) {
	for _, line := range []string{
		`    - false || trap 'rm -f "$t"' EXIT`,
		`    - while true; do trap 'x' EXIT; done`,
		`    - if a; then :; else trap 'x' EXIT; fi`,
		`    - cd "$CI_PROJECT_DIR" && trap 'rm -f "$t"' EXIT`,
		`    - echo "go"; t=$(mktemp)`,
		`    - "cd \"$D\" && trap 'x' EXIT"`,
		`    - 'trap ''rm -f "$t"'' EXIT'`,
		`    - trap 'x' "EX"IT`,
		`    - trap 'x' E'XIT'`,
		`    - trap 'x' \EXIT`,
		`    - trap 'x' $'EXIT'`,
		`    - trap 'x' SIGEXIT`,
		`    - ! trap 'x' EXIT`,
		// Fourth review of PR #327.
		`    - "trap 'x' EXIT" # note`,
		`    - 't=$(mktemp)' # note`,
		`    - trap 'x' EXIT>/dev/null`,
		`    - trap 'x' EXIT 2>/dev/null`,
		`    - readonly t=$(mktemp)`,
		`    - local t=$(mktemp)`,
		`    - declare t=$(mktemp)`,
		"    - t=`mktemp`",
		`    - t=$( mktemp )`,
		`    - t=$(TMPDIR=/x mktemp)`,
		`    - t=$(command mktemp)`,
		`    - t=${T:-$(mktemp)}`,
		`    - x=1 t=$(mktemp)`,
		`    - if t=$(mktemp); then echo ok; fi`,
		`    - if trap 'x' EXIT; then :; fi`,
		`    - while trap 'x' EXIT; do break; done`,
		`    - eval "trap 'rm -f $t' EXIT"`,
		`    - FOO=1 trap 'x' EXIT`,
		`    - command trap 'x' EXIT`,
		`    - time trap 'x' EXIT`,
		`  before_script: trap 'rm -f "$t"' EXIT`,
		`  script: ["t=$(mktemp)", "trap 'x' EXIT"]`,
		`      - run: trap 'x' EXIT`,
		`      - run: t=$(mktemp)`,
		"    - |\n      trap 'rm -f \"$t\"' \\\n        EXIT",
		"    - |\n      t=$(\\\n        mktemp)",
		"    - >\n      trap 'rm -f \"$t\"'\n      EXIT",
		"  before_script: >-\n    t=$(mktemp)",
		// Main QA of 4d823d1 (2026-11-16): a backslash ending a comment
		// does not continue it, so the trap on the next line is read.
		"    # example ending in backslash \\\n    - trap 'echo catch-me' EXIT",
		"    - make # note \\\n    - trap 'echo catch-me' EXIT",
		"    - set -e; t=$(mktemp)",
		"    - x=1 t=$( mktemp )",
		// A README fence line is sh, not YAML: its quotes are sh's
		// (fourth review: unquoting it as YAML had shifted every pairing).
		`"$CI_PROJECT_DIR/setup" && trap 'rm -f "$t"' "EXIT"`,
		`"$HOME/setup" && t="$(mktemp)"`,
	} {
		if !leakedIntoJob.MatchString(line) {
			t.Errorf("not caught: %s", line)
		}
	}
	for _, line := range []string{
		`    - ( trap 'rm -f "$t"' EXIT; make )`,
		`    - (trap 'x' EXIT; make)`,
		`    - ( make; trap 'x' EXIT )`,
		`    # see note; trap 'x' EXIT`,
		`    - make # then trap 'x' EXIT`,
		`    - sh -c 'd=$(mktemp -d); trap "rm -rf $d" EXIT; make'`,
		`    - echo "a; trap 'x' EXIT"`,
		`    - trap EXIT`,
		`    - trap - EXIT`,
		`    - trap -- - EXIT`,
		`    - echo trap 'x' EXIT`,
		`    - printf '%s\n' "t=$(mktemp)"`,
		`    - trap 'x' TERM 2>/dev/null`,
		`"$HOME/setup" && echo "done"`,
		`  script: [ "echo one", "echo two" ]`,
		`  image: alpine:3.20`,
		// Main QA of 4d823d1 (2026-11-16): a child shell's assignment and
		// trap are the child's, and text that mentions $(mktemp) assigns
		// nothing.
		`    - sh -c 'set -eu; t=$(mktemp); trap "rm -f $t" EXIT; echo child-done'`,
		`    - printf '%s' 'No install - run t=$(mktemp) first'`,
		`    - echo "t=$(mktemp)"`,
		`    - echo t=$(mktemp)`,
		// A README line that is one quoted word is a command of that name to
		// sh, not a trap: only a YAML value is unquoted as YAML.
		`"trap 'x' EXIT"`,
	} {
		if leakedIntoJob.MatchString(line) {
			t.Errorf("wrongly caught: %s", line)
		}
	}
}
