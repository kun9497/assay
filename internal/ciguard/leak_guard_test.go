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
// It does not follow the shell. It refuses a line on sight when the line,
// outside single quotes and outside a $( ) (a subshell), holds
//
//  1. the word eval, in any quoting and at any position;
//  2. the word trap, unless it resets (`trap - SIG...`, `trap SIG`) or every
//     signal is written out and is neither EXIT nor 0 (EXIT in any case, with
//     or without SIG; any number but 1-99 counts as 0) and the handler is
//     literal text that passes this same rule -- a job's own
//     `trap 'echo stopping' TERM` is its business (main QA of 67e2cf6
//     refused it once), but `trap 'trap : EXIT' DEBUG` is an EXIT trap;
//  3. a command word that holds an expansion ($x, "$x", ${x}, $(...), "$@",
//     tr$x, $'...') and no literal / outside it, or an unquoted { (bash
//     expands {trap,:,EXIT}); `"$bin/assay" version` names a file, which is
//     never a builtin, so it passes, and `$SUDO make` does not;
//  4. NAME=$(mktemp) in the spellings mktempAssign knows.
//
// and, because the rule cannot pair what it does not read, a line with a
// backtick, a quote inside ${ }, a ${ cmd; } substitution, a case inside a
// $( ), or a quote, ${ or double-quoted $( still open at its end. No state passes from one command to the next: no variable table, no
// reading of what eval would run, no conditional, function or pipeline
// scopes. "Command word" is the first word after an operator or a keyword,
// past assignments, redirections and command/builtin/time/!.
//
// It over-refuses on purpose: `c='echo ok'; eval "$c"`, `( trap : EXIT )`,
// `echo trap x EXIT`, `$SUDO make`, a string that spans lines. A refusal is
// loud -- a document test goes red and a human looks -- and the documents
// use none of this. The reader this replaces followed variables, eval
// strings, conditional scopes and pipeline children through 1,150 lines
// (1,870 on the branch after it); six review rounds each found bash it
// misread, in both directions, while every sweep of the repository's own
// documents produced the same single refusal, a mktemp assignment.
//
// Accepted though they leak -- each is pinned in leakRows so this list
// cannot drift:
//
//   - an alias for trap or eval;
//   - a file read by . or source, and a function, script or trap handler
//     defined anywhere but in the job's own text;
//   - a builtin other than eval and trap that runs a string as commands
//     (bash's `mapfile -C`);
//   - an unquoted expansion ahead of a slash whose value splits into
//     `trap ... EXIT` and a path (p='trap : EXIT '; $p/x);
//   - a glob as the command word, when the working directory holds a file
//     named trap or eval (tra? : EXIT);
//   - a mktemp path that reaches a variable some other way than
//     NAME=$(mktemp): `read -r t < <(mktemp)`, t=$(sudo mktemp).
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
		if refusedOnSight(line) {
			return line
		}
	}
	return ""
}

// ---- the rule ----

// mktempAssign finds an assignment of a mktemp path anywhere in a line,
// before quote removal: NAME=$(mktemp), NAME="$( mktemp )", NAME=`mktemp`,
// NAME=$(TMPDIR=x mktemp), NAME=${X:-$(mktemp)} -- at the line's start or
// after a blank, an operator or a double quote (export "t=$(mktemp)"). It is
// read over the line with its
// single-quoted text blanked (blankSingleQuoted), so it refuses every line
// 4d823d1 refused except those whose mktemp is quoted text that never runs
// in this shell -- the script of sh -c '...', the string printf '...' prints
// (main QA of 4d823d1, 2026-11-16).
var mktempAssign = regexp.MustCompile("(?:^|[ \\t;&|(){\"])\\w+=[\"']*(?:\\$\\{\\w+:?[-=+]\\s*)?(?:\\$\\(\\s*(?:\\w+=\\S*\\s+)*(?:command\\s+)?|`\\s*)mktemp\\b")

// blankSingleQuoted is cmd with the text of every single-quoted string --
// outside double quotes, where ' is a quote -- replaced by underscores, or
// cmd unchanged when a substitution ($( or `) or a $'...' string sits outside
// single quotes: quotes nest inside a substitution ("$(echo "it's")"), and
// with the line left as written mktempAssign refuses what 4d823d1 refused.
// The QA's two false positives quote their $(mktemp) whole, so they are
// still blanked.
func blankSingleQuoted(cmd string) string {
	b := []byte(cmd)
	dq := false
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case c == '$' && i+1 < len(b) && (b[i+1] == '(' || (b[i+1] == '\'' && !dq)), c == '`':
			return cmd
		case c == '\\' && i+1 < len(b):
			// An escaped quote is no quote: it's.
			i++
		case c == '"':
			dq = !dq
		case c == '\'' && !dq:
			for i++; i < len(b) && b[i] != '\''; i++ {
				b[i] = '_'
			}
		}
	}
	return string(b)
}

// shWord is one word of a line after quote removal, or an operator that
// ends a command (sep).
type shWord struct {
	text   string
	sep    bool
	target bool // a redirection's operand, never a command
	dyn    bool // holds an expansion, so its text is not what runs
	path   bool // holds a literal / outside ${ }
	curly  bool // holds an unquoted {
}

// caseWord is the keyword case inside a substitution's text.
var caseWord = regexp.MustCompile(`(?:^|[\s;&|(])case\s`)

// maxSubstitutionDepth bounds $( inside $( ; deeper is refused rather than
// read, which also bounds what one hostile line can cost.
const maxSubstitutionDepth = 16

// lexShell splits s from i into words and separators: quotes removed, a
// redirection's operand marked, ${ } kept whole, the text of a $( ) dropped
// -- it runs in a subshell, and is read only to find where it ends. It
// returns at the ) that closes the $( it was called for (depth > 0), or at
// the end of s. ok is false for what the header lists as unpaired.
func lexShell(s string, i, depth int) (toks []shWord, end int, ok bool) {
	var cur strings.Builder
	var w shWord
	in, target, dq := false, false, false
	brace, parens, dollar := 0, 0, -2 // dollar: where the last unescaped $ stood
	flush := func() {
		if in {
			w.text, w.target = cur.String(), target
			toks, target = append(toks, w), false
		}
		w, in = shWord{}, false
		cur.Reset()
	}
scan:
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			if i++; i < len(s) {
				in = true
				cur.WriteByte(s[i])
			}
		case c == '`':
			// Its quoting nests by backslashes; not read.
			return nil, i, false
		case c == '"' || (c == '\'' && !dq):
			if brace > 0 {
				// Whether a quote inside ${ } is a quote depends on the
				// operator: "${x#'"'}" quotes one ", "${x:-'"'}" opens one.
				return nil, i, false
			}
			in = true
			if c == '"' {
				dq = !dq
				break
			}
			// $'...' takes backslash escapes; \$'...' is a plain string.
			ansi := dollar == i-1
			for i++; i < len(s) && s[i] != '\''; i++ {
				if ansi && s[i] == '\\' && i+1 < len(s) {
					i++
				}
				cur.WriteByte(s[i])
			}
			if i >= len(s) {
				return nil, i, false
			}
		case c == '$':
			in, w.dyn, dollar = true, true, i
			cur.WriteByte(c)
			if i+1 < len(s) && s[i+1] == '{' {
				if i+2 < len(s) && strings.IndexByte(" \t|", s[i+2]) >= 0 {
					// bash 5.3's ${ cmd; } runs in this shell.
					return nil, i, false
				}
				brace++
				i++
			} else if i+1 < len(s) && s[i+1] == '(' {
				if depth >= maxSubstitutionDepth {
					return nil, i, false
				}
				_, e, ok := lexShell(s, i+2, depth+1)
				// A case pattern's ) closes it early, and what follows is
				// then read in the wrong place: $(case a in a) :;; esac)#x
				// is one word, not a comment (fourth review of PR #327).
				if !ok || caseWord.MatchString(s[i+2:e]) {
					return nil, i, false
				}
				i = e
			}
		case c == '}' && brace > 0:
			brace--
		case dq || brace > 0:
			w.path = w.path || (c == '/' && brace == 0)
			cur.WriteByte(c)
		case c == ' ' || c == '\t':
			flush()
		case c == '#' && !in:
			break scan
		case c == ')' && depth > 0 && parens == 0:
			flush()
			return toks, i, true
		case strings.IndexByte(";&|()\n", c) >= 0:
			// A ( ) is not skipped: what a subshell holds is read as this
			// shell's, and a case pattern's ) has no ( to pair with.
			if c == '(' {
				parens++
			} else if c == ')' && parens > 0 {
				parens--
			}
			flush()
			toks, target = append(toks, shWord{sep: true}), false
		case c == '<' || c == '>':
			if in && descriptor.MatchString(cur.String()) {
				// 2> : the descriptor is the redirection's.
				in = false
			}
			flush()
			for i+1 < len(s) && strings.IndexByte("<>&|", s[i+1]) >= 0 {
				i++
			}
			target = true
		default:
			in = true
			w.path = w.path || c == '/'
			w.curly = w.curly || c == '{'
			cur.WriteByte(c)
		}
	}
	flush()
	return toks, len(s), !dq && brace == 0
}

var (
	// rearmWords put the next word in command position wherever they stand:
	// `function g { $c; }` has its { after an argument.
	rearmWords = map[string]bool{"{": true, "if": true, "then": true, "elif": true, "else": true, "while": true, "until": true, "do": true}
	// prefixWords run the word after them in this shell, when they are
	// themselves in command position ([ ! "$x" ] is a test's argument).
	prefixWords = map[string]bool{"!": true, "time": true, "command": true, "builtin": true, "-p": true, "--": true}
	assignment  = regexp.MustCompile(`^[A-Za-z_]\w*(\[[^\]]*\])?\+?=`)
	descriptor  = regexp.MustCompile(`^[0-9]+$`)
	// plainWord cannot expand into a handler and a signal.
	plainWord = regexp.MustCompile(`^[A-Za-z0-9+-]+$`)
	// otherSignal is a signal written out, SIG already removed. Bash reads
	// 00, +0, -0 and " 0" as 0, so a number is taken only as 1-99.
	otherSignal = regexp.MustCompile(`^([A-Z][A-Z0-9+-]*|[1-9][0-9]?)$`)
)

// refusedOnSight is the rule over one line of sh.
func refusedOnSight(line string) bool {
	if mktempAssign.MatchString(blankSingleQuoted(line)) {
		return true
	}
	toks, _, ok := lexShell(line, 0, 0)
	if !ok {
		return true
	}
	cmdPos := true
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.sep:
			cmdPos = true
		case t.target:
		case t.text == "eval":
			return true
		case t.text == "trap":
			n := i + 1
			for n < len(toks) && !toks[n].sep {
				n++
			}
			if trapRefused(toks[i+1 : n]) {
				return true
			}
			// Its operands are judged; reading them again as words would
			// also make a line of traps quadratic.
			i = n - 1
		case rearmWords[t.text]:
			cmdPos = true
		case !cmdPos || prefixWords[t.text] || assignment.MatchString(t.text):
		case t.dyn && !t.path, t.curly:
			return true
		default:
			cmdPos = false
		}
	}
	return false
}

// trapRefused judges a trap's operands: accepted are a print or a reset, and
// a handler for signals that are all written out and not EXIT.
func trapRefused(operands []shWord) bool {
	var args []shWord
	for _, t := range operands {
		if !t.target {
			args = append(args, t)
		}
	}
	if len(args) > 0 && args[0].text == "--" {
		args = args[1:]
	}
	switch {
	case len(args) == 0:
		return false
	case len(args) == 1:
		// trap EXIT resets; trap $x may split into a handler and EXIT.
		return !plainWord.MatchString(args[0].text)
	case args[0].text == "-":
		return false
	}
	for _, sig := range args[1:] {
		name := strings.TrimPrefix(strings.ToUpper(sig.text), "SIG")
		if name == "EXIT" || !otherSignal.MatchString(name) {
			return true
		}
	}
	// The handler is this shell's commands when the signal arrives -- for
	// DEBUG, before the next command.
	return args[0].dyn || refusedOnSight(args[0].text)
}

// ---- reading the document ----

// mappingKey is a YAML mapping key with a scalar after it on the same line.
var mappingKey = regexp.MustCompile(`^[A-Za-z_][\w-]*:[ \t]+`)

// fenceLine opens or closes a README's fenced example; it is not sh.
var fenceLine = regexp.MustCompile("^```[\\w-]*$")

// documentLineRefused is refusedOnSight for a line of a document: a YAML
// item or mapping value (`- ...`, `script: ...`, `run: ...`, a flow sequence
// `[a, b]`) is unquoted as YAML does first. A README fence line is sh, not
// YAML: its quotes are sh's.
func documentLineRefused(line string) bool {
	s := strings.TrimSpace(line)
	if fenceLine.MatchString(s) {
		return false
	}
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
		return refusedOnSight(s)
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		for _, item := range flowItems(s[1 : len(s)-1]) {
			if refusedOnSight(yamlUnquote(item)) {
				return true
			}
		}
		return false
	}
	return refusedOnSight(yamlUnquote(s))
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
