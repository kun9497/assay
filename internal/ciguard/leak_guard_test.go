package ciguard

import (
	"regexp"
	"strings"
)

// leakGuard refuses what an install job could use to leave something in the
// calling shell: a variable holding a mktemp path, or a trap on EXIT. GitLab
// runs before_script and script in one shell, so either reaches the job's
// own steps -- the four-line form's `trap 'rm -f "$t"' EXIT` deleted a
// report.txt a later step had put in t (main QA of ef0bc1a, 2026-11-13).
//
// It is a lint over this repository's examples, not a shell reader. It looks
// at the text of a line, with quoted strings blanked and comments cut, and refuses on sight:
//
//  1. the word eval;
//  2. the word trap, unless it resets (`trap - EXIT`) or its handler is one
//     single-quoted string and every signal is TERM, INT, HUP or QUIT -- a
//     job's own `trap 'echo stopping' TERM` is its business (main QA of
//     67e2cf6 refused it once);
//  3. a command that begins with an expansion and has no / in its first
//     word: `$SUDO make` and `"$@"` are refused, `"$bin/assay" version`
//     names a file and passes;
//  4. NAME=$(mktemp), in the spellings mktempAssign knows.
//
// Single-quoted text is not this shell's commands -- the script of
// `sh -c '...'`, which is what the README's one-liner is -- and is not read.
// Everything else on the line is, wherever it stands: a trap in a subshell,
// in a $( ) or in an echoed string is refused like any other. That is on
// purpose. A refusal is loud: a document test goes red and a person looks.
//
// What it does not do is follow the shell, and it does not claim to catch a
// spelling built to hide: tr""ap, e\val, a word assembled from a variable,
// an alias, a sourced file, a function defined elsewhere. The reader this
// replaces tried to. It followed variables, eval strings, conditional
// scopes and pipeline children through 1,150 lines (1,870 on the branch
// after it), a first rewrite still carried a 200-line lexer, and seven
// review rounds each found bash that was misread, in both directions --
// while every sweep of the repository's own documents produced one refusal,
// a plain mktemp assignment. The examples are written by maintainers
// copying the documented form, so the plain spellings are the ones that
// occur.
type leakGuard struct{}

// leakedIntoJob is the guard, read over the install jobs only (installJobs).
var leakedIntoJob leakGuard

// FindString is the first line of a document that is refused, "" when none
// is. A document's lines are YAML or a README's as well as sh, so each goes
// through documentLineRefused.
func (leakGuard) FindString(text string) string {
	for _, line := range logicalLines(text) {
		if documentLineRefused(line) {
			return line
		}
	}
	return ""
}

// MatchString reports whether any line of text is refused.
func (g leakGuard) MatchString(text string) bool { return g.FindString(text) != "" }

// firstShellLeak is FindString for a decoded run scalar, which is already
// shell source: YAML quoting and folding were the decoder's, so only sh's
// own line continuation is joined, indentation kept.
func firstShellLeak(script string) string {
	lines := strings.Split(script, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		for continues(line) && i+1 < len(lines) {
			i++
			line = line[:len(line)-1] + lines[i]
		}
		if refusedOnSight(line, true) {
			return line
		}
	}
	return ""
}

// ---- the rule ----

// mktempAssign finds an assignment of a mktemp path anywhere in a line:
// NAME=$(mktemp), NAME="$( mktemp )", NAME=`mktemp`, NAME=$(TMPDIR=x mktemp),
// NAME=${X:-$(mktemp)} -- at the line's start or after a blank, an operator
// or a double quote (export "t=$(mktemp)"). The double quote makes it refuse
// `echo "report=$(mktemp)" >> "$GITHUB_OUTPUT"` too, which sets nothing:
// telling the two apart needs the word reading this guard gave up.
var mktempAssign = regexp.MustCompile("(?:^|[ \\t;&|(){\"])\\w+=[\"']*(?:\\$\\{\\w+:?[-=+]\\s*)?(?:\\$\\(\\s*(?:\\w+=\\S*\\s+)*(?:command\\s+)?|`\\s*)mktemp\\b")

var (
	evalWord = regexp.MustCompile(`\beval\b`)
	trapWord = regexp.MustCompile(`\btrap\b`)
	// trapEnd is where a trap command's own words stop.
	trapEnd = regexp.MustCompile(`[;&|()]`)
	// trapReset is `trap - SIG...`, after an optional `--`.
	trapReset = regexp.MustCompile(`^(?:--\s+)?-(?:\s+\w+)*$`)
	// trapOther is a single-quoted handler and what follows it.
	trapOther = regexp.MustCompile(`^(?:--\s+)?'[^']*'((?:\s+\S+)+)$`)
	// otherSignal is a signal written out, quotes and SIG removed: a name,
	// or a number that is not 0 however it is padded.
	otherSignal = regexp.MustCompile(`^(?:[A-Z][A-Z0-9]*|[1-9][0-9]?)$`)
	// expansionLed is a command whose first word begins with an expansion
	// and holds no slash: at the line's start or after an operator, a
	// keyword or a builtin that runs its argument, past NAME=value words.
	expansionLed = regexp.MustCompile("(?:^|[;&|({!]|\\b(?:then|do|else|elif|if|while|until|time|command|builtin|exec)[ \\t])[ \\t]*(?:\\w+=\\S*[ \\t]+)*\"?[$`][^ \\t/]*(?:[ \\t]|$)")
)

// refusedOnSight is the rule over one line. commands is false for text that
// is not a command line -- a YAML mapping value such as
// `IMAGE: $CI_REGISTRY_IMAGE` -- where rule 3 would read a value as a
// command; the other three rules need no command position and still apply.
//
// eval and trap are looked for outside every quoted string: the text of
// `echo "a; trap 'x' EXIT"` and the script of `sh -c "..."` are not this
// shell's commands. The mktemp assignment and the expansion-led command are
// looked for with double-quoted text kept, since t="$(mktemp)" and
// "$cmd" are written inside it.
func refusedOnSight(line string, commands bool) bool {
	single := cutComment(blankQuoted(line, false))
	if mktempAssign.MatchString(single) || (commands && expansionLed.MatchString(single)) {
		return true
	}
	// Blanking keeps every byte's position, so a trap found in the blanked
	// text is read from the line as written, quoted signals and all.
	both := cutComment(blankQuoted(line, true))
	if evalWord.MatchString(both) {
		return true
	}
	for _, at := range trapWord.FindAllStringIndex(both, -1) {
		end := len(both)
		if m := trapEnd.FindStringIndex(both[at[1]:]); m != nil {
			end = at[1] + m[0]
		}
		if !trapAccepted(strings.TrimSpace(line[at[1]:end])) {
			return true
		}
	}
	return false
}

// trapAccepted reports whether a trap's operands, as written, reset it or
// name only signals other than EXIT behind one single-quoted handler.
func trapAccepted(operands string) bool {
	if trapReset.MatchString(operands) {
		return true
	}
	m := trapOther.FindStringSubmatch(operands)
	if m == nil {
		return false
	}
	for _, sig := range strings.Fields(m[1]) {
		if n := len(sig); n >= 2 && strings.ContainsRune(`"'`, rune(sig[0])) && sig[n-1] == sig[0] {
			sig = sig[1 : n-1]
		}
		sig = strings.TrimPrefix(strings.ToUpper(sig), "SIG")
		if sig == "EXIT" || !otherSignal.MatchString(sig) {
			return false
		}
	}
	return true
}

// blankQuoted is s with the text of every single-quoted string replaced by
// underscores, and of every double-quoted one too when double is set. A
// single quote inside double quotes is a character, and an escaped quote is
// no quote. A quote left open blanks to the end of the line.
func blankQuoted(s string, double bool) string {
	const backslash, squote, dquote = 0x5c, 0x27, 0x22
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case backslash:
			i++
		case squote:
			for i++; i < len(b) && b[i] != squote; i++ {
				b[i] = '_'
			}
		case dquote:
			for i++; i < len(b) && b[i] != dquote; i++ {
				escaped := b[i] == backslash && i+1 < len(b)
				if double {
					b[i] = '_'
				}
				if escaped {
					i++
					if double {
						b[i] = '_'
					}
				}
			}
		}
	}
	return string(b)
}

// cutComment is s up to a # that begins a word. Quoted text is blanked
// before this is called, apart from double-quoted text when the caller kept
// it, which is why double quotes are still tracked here. `make # then trap x
// EXIT` says nothing about the job; a#b and $# are not comments.
func cutComment(s string) string {
	const backslash, dquote = 0x5c, 0x22
	dq := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == backslash:
			i++
		case c == dquote:
			dq = !dq
		case c == '#' && !dq && (i == 0 || strings.IndexByte(" \t;", s[i-1]) >= 0):
			return s[:i]
		}
	}
	return s
}

// ---- reading the document ----

// mappingKey is a YAML mapping key with a scalar after it on the same line.
var mappingKey = regexp.MustCompile(`^[A-Za-z_][\w-]*:[ \t]+`)

// scriptKey is a mapping key whose value is a command line.
var scriptKey = regexp.MustCompile(`^(?:script|before_script|after_script|run):`)

// fenceLine opens or closes a README's fenced example; it is not sh.
var fenceLine = regexp.MustCompile("^```[\\w-]*$")

// documentLineRefused is refusedOnSight for a line of a document: a YAML
// item or mapping value (`- ...`, `script: ...`, `run: ...`, a flow sequence
// `[a, b]`) is unquoted as YAML does first. The value of any other key
// (`IMAGE: $CI_REGISTRY_IMAGE`, `- if: $CI_COMMIT_TAG`) is not a command
// line. A line inside a README's fence is sh, not YAML: its quotes are sh's.
func documentLineRefused(line string) bool {
	s := strings.TrimSpace(line)
	if fenceLine.MatchString(s) {
		return false
	}
	yamlValue, commands := false, true
	if strings.HasPrefix(s, "- ") || s == "-" {
		s = strings.TrimSpace(strings.TrimPrefix(s, "-"))
		yamlValue = true
	}
	if m := mappingKey.FindString(s); m != "" {
		commands = scriptKey.MatchString(m)
		s = strings.TrimSpace(s[len(m):])
		yamlValue = true
	}
	if !yamlValue {
		return refusedOnSight(s, true)
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		for _, item := range flowItems(s[1 : len(s)-1]) {
			if refusedOnSight(yamlUnquote(item), commands) {
				return true
			}
		}
		return false
	}
	return refusedOnSight(yamlUnquote(s), commands)
}

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
//
// A # opens a comment when it begins a token: after the line's start, a
// blank, or an operator (; & | ( and the ) of a subshell). The ) of a $( )
// is inside the word: $(date)#tag is one word (second review), (make)# note
// is a comment (third review); a#b and $# are not comments. A ) that pairs
// with nothing -- a case pattern's inside $( ) has taken its $( -- is not
// taken for a subshell's: reading on is the loud side (fourth review).
func continues(line string) bool {
	// Only a backslash immediately before the physical newline can escape
	// it. In a literal YAML block a trailing space or tab is shell input.
	s := line
	if !strings.HasSuffix(s, "\\") {
		return false
	}
	quote := byte(0)
	var open []bool // the ( still open outside quotes; true for a $(
	afterSubshell := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		subshellClosed := afterSubshell
		afterSubshell = false
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else if c == '\\' && i == len(s)-1 {
				// sh keeps it, but the quote goes on to the next line, so
				// the two are read as one (second review: a trap whose
				// single-quoted handler spans lines had stopped being read).
				return true
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
		case c == '(':
			open = append(open, i > 0 && s[i-1] == '$')
		case c == ')':
			if n := len(open); n > 0 {
				afterSubshell = !open[n-1]
				open = open[:n-1]
			}
		case c == '#' && (i == 0 || subshellClosed || strings.IndexByte(" \t;&|(", s[i-1]) >= 0):
			return false
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
// with its backslash escapes, '...' with a doubled quote for one quote -- a
// trailing YAML comment after the closing quote dropped. Anything else is s.
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
