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
// It reads each line as sh would rather than as a pattern: the YAML list
// item and YAML quoting come off, the line splits into commands at ; && ||
// & and | outside quotes, a subshell `( ... )` and a comment are skipped,
// leading `{` `then` `do` `else` `!` `export` come off a command, and the
// command's words go through sh's quote removal. Three review rounds of PR
// #327 had found a regex for this leaking in both directions: a quoted
// signal name (`"EXIT"`, `"EX"IT`), `trap --`, a trap after another command
// or in a compound body, or after a command whose argument is quoted, all
// let through; a trap inside `sh -c '...'` or a subshell, or a comment
// mentioning one, refused. A trap on TERM or INT alone is a job's own
// business, not the installer's leftover (main QA of 67e2cf6, 2026-11-13:
// `trap 'echo stopping' TERM` in an independent GitLab job was refused).
type leakGuard struct{}

// leakedIntoJob is the guard, read over the install jobs only (installJobs).
var leakedIntoJob leakGuard

// mktempAssign is a command assigning a mktemp path: NAME=$(mktemp ...),
// quoted or not, before quote removal.
var mktempAssign = regexp.MustCompile(`^\w+="?\$\(mktemp\b`)

// FindString is the first line of text that leaks, "" when none does.
func (leakGuard) FindString(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if lineLeaks(line) {
			return line
		}
	}
	return ""
}

// MatchString reports whether any line of text leaks.
func (g leakGuard) MatchString(text string) bool { return g.FindString(text) != "" }

func lineLeaks(line string) bool {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "- ") || s == "-" {
		s = strings.TrimSpace(strings.TrimPrefix(s, "-"))
	}
	s = yamlUnquote(s)
	for _, cmd := range shellCommands(s) {
		if commandLeaks(cmd) {
			return true
		}
	}
	return false
}

// yamlUnquote is s as YAML reads a flow scalar quoted whole: "..." with its
// backslash escapes, '...' with ” for a quote. Anything else is s.
func yamlUnquote(s string) string {
	if len(s) < 2 {
		return s
	}
	switch {
	case s[0] == '"' && s[len(s)-1] == '"':
		var b strings.Builder
		in := s[1 : len(s)-1]
		for i := 0; i < len(in); i++ {
			if in[i] == '\\' && i+1 < len(in) {
				i++
			}
			b.WriteByte(in[i])
		}
		return b.String()
	case s[0] == '\'' && s[len(s)-1] == '\'':
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}

// shellCommands splits one line of sh into its simple commands at the
// separators that end one outside quotes. A subshell `( ... )` at a
// command's start is dropped -- what it sets dies with it -- and so is a
// comment, from an unquoted # that starts a word.
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

// commandLeaks reports whether one simple command leaves a mktemp variable
// or an EXIT trap in the shell that runs it.
func commandLeaks(cmd string) bool {
	for {
		trimmed := cmd
		for _, kw := range []string{"{", "then", "do", "else", "!", "export"} {
			if strings.HasPrefix(trimmed, kw+" ") || strings.HasPrefix(trimmed, kw+"\t") {
				trimmed = strings.TrimSpace(trimmed[len(kw):])
			}
		}
		if trimmed == cmd {
			break
		}
		cmd = trimmed
	}
	if mktempAssign.MatchString(cmd) {
		return true
	}
	words := shellWords(cmd)
	if len(words) == 0 || words[0] != "trap" {
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
// escaping the next byte.
func shellWords(cmd string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
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
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

// The third review of PR #327, line by line: what a reader adapting the
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
	} {
		if !leakedIntoJob.MatchString(line) {
			t.Errorf("not caught: %s", line)
		}
	}
	for _, line := range []string{
		`    - ( trap 'rm -f "$t"' EXIT; make )`,
		`    - (trap 'x' EXIT; make)`,
		`    # see note; trap 'x' EXIT`,
		`    - make # then trap 'x' EXIT`,
		`    - sh -c 'd=$(mktemp -d); trap "rm -rf $d" EXIT; make'`,
		`    - echo "a; trap 'x' EXIT"`,
		`    - trap EXIT`,
		`    - trap - EXIT`,
		`    - trap -- - EXIT`, // a reset, after the option separator
		`    - echo trap 'x' EXIT`,
		`    - printf '%s\n' "t=$(mktemp)"`,
	} {
		if leakedIntoJob.MatchString(line) {
			t.Errorf("wrongly caught: %s", line)
		}
	}
}
