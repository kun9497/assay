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
// elif while until time command builtin export readonly local declare
// typeset`, leading NAME=value assignments) come off, `case WORD in` and an
// arm's pattern come off a case arm's command and a function's header off its
// body, `eval`'s argument is read again, and the words go through sh's quote
// removal. Four review rounds of PR #327 found a regex for this leaking both
// ways.
//
// It is a lint over this repository's examples, held to what a reader
// rewriting the four-line form would plausibly write, not a shell parser.
// Where it cannot be sure it refuses, and it proves nothing it does not have
// to. A trap on TERM or INT alone is a job's own business, not the
// installer's leftover (main QA of 67e2cf6, 2026-11-13: `trap 'echo
// stopping' TERM` in an independent job was refused).
//
// A stored string reaches eval, or is run as a command, as one of three
// things: a literal the guard read, which it reads again as commands; a name
// never written in this shell, which is the environment's and left alone; or
// unknown, which is refused. A value is a literal only when it was assigned
// where the assignment certainly ran. Unknown, then, is everything assigned
// or unset
//   - after && or ||, in an if, a loop, a case arm or a function body (a
//     name a function body writes stays unknown for good: the body runs
//     whenever it is called);
//   - inside an eval string, whether or not the string parses -- telling a
//     string eval would run from one it would reject is a parser's work, and
//     three rounds of counting if against fi still accepted `then`, a stray
//     `)` and an open quote (review of a09f948);
//   - by NAME+=, `for NAME`, `read NAME`, `printf -v NAME`, ${NAME:=...}, or
//     a prefix assignment to a POSIX special builtin, which may persist.
//
// Refused though sh would not leave them in the job shell, on the same loud
// side:
//   - an assignment after `command` or `time`, one before a regular command
//     (t=$(mktemp) make), which only that command's environment sees, and a
//     NAME=$(mktemp) after a blank anywhere outside single quotes (echo
//     t=$(mktemp)), which mktempAssign reads as 4d823d1 did;
//   - an eval of a name an eval string assigned, of a partially expanded
//     stored name (eval "$c;"), of ${!name}, or of a command substitution
//     (eval "$(ssh-agent -s)");
//   - a trap whose signal is an expansion, and the last stage of a pipeline,
//     which may run in the parent (bash lastpipe), a continued pipeline line
//     with it;
//   - a brace group in a pipeline or the background that assigns, unsets,
//     traps or evals: its commands were read as the job shell's, so what they
//     changed here is wrong. A group that does none of those is accepted;
//   - an assignment to a name that an eval or a command word earlier in the
//     same open loop, or in any function body, reads -- the read happens
//     again after the assignment -- and a trap or mktemp in a case arm or a
//     function body that never runs;
//   - a function whose body is not a brace group.
//
// Not read, and so a miss: a multi-line subshell `(` ... `)` and a heredoc's
// body (both read as the job shell's commands, so a trap in one is refused
// and a reassignment in one is believed); a trap or mktemp after a
// quote-spanning multi-line string; `trap $args` with handler and signal in
// one expansion; an unset name before a command ($none trap ...).
type leakGuard struct{}

// leakedIntoJob is the guard, read over the install jobs only (installJobs).
var leakedIntoJob leakGuard

// mktempAssign finds an assignment of a mktemp path anywhere in a command,
// before quote removal: NAME=$(mktemp), NAME="$( mktemp )", NAME=`mktemp`,
// NAME=$(TMPDIR=x mktemp), NAME=${X:-$(mktemp)} -- at the command's start or
// after a space. It is the conservative half of the check, read over the
// command with its single-quoted text blanked (blankSingleQuoted), so it
// refuses every line 4d823d1 refused except those whose mktemp is quoted
// text that never runs in this shell -- the script of sh -c '...', the
// string printf '...' prints (main QA of 4d823d1, 2026-11-16). Four review
// rounds of reading assignments word by word kept finding real leaks the
// pattern had caught: nested quotes, a function body, a case arm.
var mktempAssign = regexp.MustCompile("(?:^|[ \\t])\\w+=[\"']?(?:\\$\\{\\w+:?[-=+]\\s*)?(?:\\$\\(\\s*(?:\\w+=\\S*\\s+)*(?:command\\s+)?|`\\s*)mktemp\\b")

// blankSingleQuoted is cmd with the text of every single-quoted string --
// outside double quotes, where ' is a quote -- replaced by underscores, or
// cmd unchanged when a substitution ($( or `) or a $'...' string sits outside
// single quotes. Quotes nest inside a substitution ("$(echo "it's")"), and a
// reader that does not track that nesting can take a real assignment for
// quoted text; with the command left as written, mktempAssign refuses what
// 4d823d1 refused (fifth review). The QA's two false positives quote their
// $(mktemp) whole, so they are still blanked.
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

// assignmentWord is a NAME=value or NAME+=value word.
var assignmentWord = regexp.MustCompile(`^\w+\+?=`)

// FindString is the first line of text that leaks, "" when none does.
func (leakGuard) FindString(text string) string {
	state := newShellState()
	for _, line := range logicalLines(text) {
		if state.lineLeaks(line) {
			return line
		}
	}
	return ""
}

func newShellState() shellState {
	return shellState{vars: map[string]string{}, unknown: map[string]bool{}, evaluating: map[string]bool{},
		poisoned: map[string]bool{}, deferred: map[string]bool{}, evalBytesLeft: 1 << 20}
}

// A decoded run scalar is already shell source. Retain indentation following
// a continued shell line and leave YAML quoting and folding to the decoder.
func firstShellLeak(script string) string {
	state := newShellState()
	lines := strings.Split(script, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		for continues(line) && i+1 < len(lines) {
			i++
			line = line[:len(line)-1] + lines[i]
		}
		if state.shellLeaks(line) {
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
	// Only a backslash immediately before the physical newline can escape
	// it. In a literal YAML block a trailing space or tab is shell input.
	s := line
	if !strings.HasSuffix(s, "\\") {
		return false
	}
	quote := byte(0)
	var parens parenScan
	for i := 0; i < len(s); i++ {
		c := s[i]
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
		case c == '#' && parens.commentStarts(s, i):
			return false
		}
	}
	return false
}

// commentStarts reports whether the # at s[i] opens a comment: it begins a
// token, so it follows the line's start, a blank, or an operator (; & | ( and
// the ) of a subshell). The ) of a $( ) is inside the word: $(date)#tag is
// one word (second review), (make)# note is a comment (third review).
// a#b and $# are not comments. (Review of the guard branch: continues had
// taken only a blank, so `make;# note \` still swallowed the next line.)
func (scan *parenScan) commentStarts(s string, i int) bool {
	if i == 0 || strings.IndexByte(" \t;&|(", s[i-1]) >= 0 {
		return true
	}
	return s[i-1] == ')' && !scan.closesSubstitution(s, i-1)
}

// parenScan is the reading closesSubstitution has done of one line. Every
// question is about a later ) of the same line, so it goes on from where the
// last one stopped: a line of `a)#a)#...` had been read from its start once
// for each #.
type parenScan struct {
	k     int
	open  []bool // true: $(
	quote byte
}

// closesSubstitution reports whether the ) at s[j] closes a $( rather than a
// subshell's (, reading the parentheses before it outside quotes.
func (scan *parenScan) closesSubstitution(s string, j int) bool {
	open, quote, k := scan.open, scan.quote, scan.k
	defer func() { scan.open, scan.quote, scan.k = open, quote, k }()
	for ; k < j; k++ {
		switch c := s[k]; {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' {
				k++
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '\\':
			k++
		case c == '(':
			open = append(open, k > 0 && s[k-1] == '$')
		case c == ')' && len(open) > 0:
			open = open[:len(open)-1]
		}
	}
	// A ) that pairs with nothing -- a case pattern's inside $( ) has
	// taken its $( -- is not taken for a subshell's: reading on is the
	// loud side (fourth review: $(case a in a) ...;; esac)#x; trap ...
	// EXIT had hidden the trap).
	return len(open) == 0 || open[len(open)-1]
}

// shellState carries what the guard knows of one install shell between its
// commands: the names whose value is a literal it read (vars) and the names
// it saw written without being able to say to what (unknown). A name in
// neither was never written here. Only eval, or a name run as a command,
// reads a stored string as shell commands.
type shellState struct {
	vars       map[string]string
	unknown    map[string]bool
	evaluating map[string]bool
	// poisoned names are written in a function body. The body runs whenever
	// the function is called, so no later assignment makes the name known.
	poisoned map[string]bool
	// deferred names are evaluated in a function body, and each loops entry
	// holds the names evaluated in one open loop. Either reads the name again
	// later than where it stands in the text, so an assignment after it is
	// refused: the value the guard read there is not the one that will run.
	deferred map[string]bool
	loops    []map[string]bool
	// replayed is set by such an assignment; shellLeaks refuses on it.
	replayed bool
	// effects counts the commands that changed or consulted this state. A
	// brace group that turns out to have run in a child is refused when the
	// count moved inside it.
	effects       int
	evalBytesLeft int
	shellScope
}

// shellScope is the part an eval string starts afresh: eval shares the
// shell's variables but parses a program of its own, so a fi or } in its
// string closes nothing of the caller's.
type shellScope struct {
	conditionalDepth   int
	braces             []braceGroup
	caseDepth          int
	functionDepth      int
	loopBase           int
	pendingConditional bool
	pendingFunction    bool
	// inEval marks the commands of an eval string. What they assign or unset
	// is unknown, never a value: whether the string parsed, and so whether
	// any of it ran, is not something this reader can prove.
	inEval bool
}

// braceGroup is one open `{`.
type braceGroup struct {
	conditional bool // opened where its commands may not run
	function    bool // a function's body
	effects     int  // shellState.effects when it opened
}

func (state *shellState) reset() {
	clear(state.vars)
	clear(state.unknown)
	clear(state.poisoned)
	clear(state.deferred)
	state.loops = nil
	state.shellScope = shellScope{}
}

func (state *shellState) lineLeaks(line string) bool {
	s := strings.TrimSpace(line)
	yamlValue := false
	if strings.HasPrefix(s, "- ") || s == "-" {
		s = strings.TrimSpace(strings.TrimPrefix(s, "-"))
		yamlValue = true
	}
	if m := mappingKey.FindString(s); m != "" {
		if strings.TrimSpace(m) == "run:" {
			// GitHub Actions starts each run step in its own shell.
			state.reset()
		}
		s = strings.TrimSpace(s[len(m):])
		yamlValue = true
	}
	if !yamlValue {
		return state.shellLeaks(s)
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		for _, item := range flowItems(s[1 : len(s)-1]) {
			if state.shellLeaks(yamlUnquote(item)) {
				return true
			}
		}
		return false
	}
	return state.shellLeaks(yamlUnquote(s))
}

func (state *shellState) shellLeaks(s string) bool {
	for _, cmd := range shellCommands(s) {
		if cmd.text == "" {
			state.pendingConditional = true
			continue
		}
		conditional := cmd.conditional || state.pendingConditional
		state.pendingConditional = false
		// A non-final pipeline stage and an asynchronous list run in a
		// child: nothing they set reaches the job shell, but the words that
		// open and close a compound command are still read from them, or
		// `if a | b; then` and `case x in a|b)` would open nothing. The
		// final pipeline stage may run in the parent (bash lastpipe).
		if state.commandLeaks(cmd.text, conditional, cmd.child) || state.replayed {
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

type simpleCommand struct {
	text        string
	child       bool
	conditional bool
}

// shellCommands splits one line of sh into its simple commands at the
// separators that end one outside quotes. A subshell `( ... )` at a
// command's start is skipped whole, so a separator inside it does not split
// off a command that is then read as the job shell's; a comment, from an
// unquoted # that starts a word, ends the line.
func shellCommands(s string) []simpleCommand {
	var cmds []simpleCommand
	var cur strings.Builder
	quote := byte(0)
	depth := 0
	atStart := true
	listStart := 0
	inPipe := false
	conditional := false
	var parens parenScan
	flush := func(operator string) {
		if c := strings.TrimSpace(cur.String()); c != "" {
			cmds = append(cmds, simpleCommand{text: c, child: operator == "|", conditional: conditional || inPipe})
		} else if operator == "" && (conditional || inPipe) {
			// Shell syntax also continues after an operator without a
			// backslash. Keep that condition across physical lines.
			cmds = append(cmds, simpleCommand{})
		}
		if operator == "&" {
			// a && b & backgrounds the whole AND-OR list.
			for i := listStart; i < len(cmds); i++ {
				cmds[i].child = true
			}
		}
		if operator == ";" || operator == "&" {
			listStart = len(cmds)
		}
		inPipe = operator == "|"
		conditional = operator == "&&" || operator == "||"
		cur.Reset()
		atStart = true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != '\'' && startsSubstitution(s, i):
			// A pipe in a command substitution belongs to the substitution.
			// The surrounding assignment is still in the calling shell.
			end := substitutionEnd(s, i)
			if depth == 0 {
				cur.WriteString(s[i:end])
			}
			i = end - 1
			atStart = false
			continue
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
		case c == ')':
			// Outside a subshell or substitution, this can close a case
			// pattern. Its | separated alternatives, not pipeline stages.
			// Retain the existing checks on the following arm.
			inPipe = false
		case c == '#' && parens.commentStarts(s, i):
			flush("")
			return cmds
		case c == '&' && i > 0 && (s[i-1] == '>' || s[i-1] == '<'):
			// 2>&1, <&3: the redirection's, not a background operator
			// (second review: 2>&1 t=$(mktemp) had split into "1 t=...").
		case c == '|' && i > 0 && s[i-1] == '>', c == '&' && i+1 < len(s) && s[i+1] == '>':
			// The | of >| and the & of bash's &> are redirections.
		case c == ';' || c == '&' || c == '|':
			end := i + 1
			if c != ';' && end < len(s) && s[end] == c {
				end++
			}
			flush(s[i:end])
			i = end - 1
			continue
		}
		if c != ' ' && c != '\t' {
			atStart = false
		}
		if depth == 0 {
			cur.WriteByte(c)
		}
	}
	flush("")
	return cmds
}

// prefixWords are the words that open a body or a condition, or run the rest
// of the command in the same shell.
var prefixWords = map[string]bool{"{": true, "then": true, "do": true, "else": true, "!": true, "if": true, "elif": true,
	"while": true, "until": true, "time": true, "command": true, "builtin": true, "export": true, "readonly": true, "local": true, "declare": true, "typeset": true}

// declarationBuiltins assign their NAME=value operands in the calling shell.
var declarationBuiltins = map[string]bool{"export": true, "readonly": true, "local": true, "declare": true, "typeset": true}

// A prefix assignment before these builtins can survive in the calling
// shell (POSIX mode), unlike a regular command's environment assignment.
var specialBuiltins = map[string]bool{":": true, ".": true, "break": true, "continue": true,
	"eval": true, "exec": true, "exit": true, "export": true, "readonly": true,
	"return": true, "set": true, "shift": true, "times": true, "trap": true, "unset": true}

func specialPrefixAssignments(words, raws []string) []string {
	var names []string
	for i, word := range words {
		if assigns(raws[i]) {
			names = append(names, assignedName(raws[i]))
			continue
		}
		if specialBuiltins[word] {
			return names
		}
		if !prefixWords[word] || declarationBuiltins[word] {
			break
		}
	}
	return nil
}

// assigns reports whether a word, as written, is a NAME=value assignment: the
// name and = unquoted, so "t=$(mktemp)" is a command name, not one.
func assigns(raw string) bool { return assignmentWord.MatchString(raw) }

// assignedName is the name a NAME=value or NAME+=value word writes.
func assignedName(raw string) string {
	name, _, _ := strings.Cut(raw, "=")
	return strings.TrimSuffix(name, "+")
}

// assignsMktemp reports whether a word, as written, assigns a mktemp path: an
// assignment whose value, read as sh reads it, runs mktemp -- double quotes
// keep the substitution ("$(mktemp)"), single quotes make it text
// ('$(mktemp)' assigns the string).
func assignsMktemp(raw string) bool {
	return assigns(raw) && mktempValue.MatchString(shView(raw))
}

// shView is a word as written with its quoting read as sh reads it for a
// substitution: double quotes dropped, single-quoted text blanked.
func shView(raw string) string {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '\'' && !(i > 0 && raw[i-1] == '\\'):
			j := strings.IndexByte(raw[i+1:], '\'')
			if j < 0 {
				j = len(raw) - i - 1
			}
			b.WriteString(strings.Repeat("_", j))
			i += j + 1
		case c == '"':
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// shellName is a variable's name.
var shellName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// defaultAssignment is an expansion that assigns: ${NAME:=value}, ${NAME=value}.
var defaultAssignment = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):?=`)

// functionName is a function definition's first word: f(), or f(){ with the
// body's brace attached.
var functionName = regexp.MustCompile(`^[A-Za-z_][\w.:-]*\(\)(\{?)$`)

// functionHeader is how many of a command's first words define a function --
// f(), f (), function f, function f () -- 0 when none do, and whether the
// last of them carries the body's opening brace.
func functionHeader(raws []string) (n int, brace bool) {
	if raws[0] == "function" && len(raws) > 1 {
		if len(raws) > 2 && raws[2] == "()" {
			return 3, false
		}
		return 2, false
	}
	if m := functionName.FindStringSubmatch(raws[0]); m != nil {
		return 1, m[1] != ""
	}
	if len(raws) > 1 && shellName.MatchString(raws[0]) && (raws[1] == "()" || raws[1] == "(){") {
		return 2, raws[1] == "(){"
	}
	return 0, false
}

// casePatternEnd is the index of the word that ends a case arm's pattern
// list -- y), "a b"), (y) -- or -1 when the command has none, as a line of an
// arm's body does not. A word with a substitution in it is a command's.
func casePatternEnd(raws []string) int {
	for i, raw := range raws {
		if !strings.HasSuffix(raw, ")") || strings.Contains(raw, "$(") {
			continue
		}
		if strings.HasPrefix(raw, "(") || strings.Count(raw, ")") > strings.Count(raw, "(") {
			return i
		}
	}
	return -1
}

// commandLeaks reports whether one simple command leaves a mktemp variable
// or an EXIT trap in the shell that runs it, or does something this reader
// cannot follow. A child's command (child) sets nothing here; it is read for
// the words that open and close a compound command only.
func (state *shellState) commandLeaks(cmd string, conditional, child bool) bool {
	if !child {
		if mktempAssign.MatchString(blankSingleQuoted(cmd)) {
			return true
		}
		// ${NAME:=value} assigns wherever its word stands, a regular
		// command's argument included.
		for _, m := range defaultAssignment.FindAllStringSubmatch(blankSingleQuoted(cmd), -1) {
			state.forget(m[1])
		}
	}
	words, raws := shellWords(cmd)
	// `case WORD in` and an arm's pattern list come off; what follows is the
	// arm's command. Which arm runs is not read, so every one is conditional.
	for patternRead := false; len(raws) > 0; {
		if state.caseDepth > 0 && !patternRead {
			patternRead = true
			if k := casePatternEnd(raws); k >= 0 {
				// A word taken for a pattern's may have been an arm body's
				// assignment beside a value that ends in ); it is not lost.
				for _, raw := range raws[:k+1] {
					if !child && assigns(raw) {
						state.forget(assignedName(raw))
					}
				}
				words, raws = words[k+1:], raws[k+1:]
				continue
			}
		}
		if raws[0] != "case" {
			break
		}
		state.caseDepth++
		state.conditionalDepth++
		k := 0
		for k < len(raws) && raws[k] != "in" {
			k++
		}
		if k == len(raws) {
			return false
		}
		words, raws = words[k+1:], raws[k+1:]
		patternRead = false
	}
	if len(raws) == 0 {
		return false
	}
	if n, brace := functionHeader(raws); n > 0 {
		words, raws = words[n:], raws[n:]
		if brace {
			words, raws = append([]string{"{"}, words...), append([]string{"{"}, raws...)
		}
		state.pendingFunction = true
		if len(raws) == 0 {
			// The body opens on the next line.
			return false
		}
	}
	if state.pendingFunction && raws[0] != "{" {
		// A function whose body is not a brace group -- f() if ...; fi,
		// f() ( ... ) -- has no end this reader tracks.
		state.pendingFunction = false
		return true
	}
	allWords, allRaws := words, raws
	switch raws[0] {
	case "for", "select":
		state.conditionalDepth++
		state.loops = append(state.loops, map[string]bool{})
		if len(words) > 1 && shellName.MatchString(words[1]) {
			state.forget(words[1])
		}
	case "fi":
		if state.conditionalDepth > 0 {
			state.conditionalDepth--
		}
	case "done":
		if state.conditionalDepth > 0 {
			state.conditionalDepth--
		}
		if len(state.loops) > state.loopBase {
			state.loops = state.loops[:len(state.loops)-1]
		}
	case "esac":
		if state.caseDepth > 0 {
			state.caseDepth--
			state.conditionalDepth--
		}
	case "}":
		n := len(state.braces)
		if n == 0 {
			// Its { was not read, so neither was what the group did.
			return child
		}
		group := state.braces[n-1]
		state.braces = state.braces[:n-1]
		if group.conditional {
			state.conditionalDepth--
		}
		if group.function {
			state.functionDepth--
		}
		if child && state.effects != group.effects {
			// The group ran in a child -- a pipeline stage, a background
			// list -- but its commands were read as the job shell's: an
			// unset or a reassignment in it erased nothing here.
			return true
		}
	}
	if !child {
		if names := specialPrefixAssignments(words, raws); len(names) > 0 {
			markUnknown := func() {
				for _, name := range names {
					state.forget(name)
				}
			}
			// Before execution protects nested eval; after execution preserves
			// uncertainty when a builtin restores or changes its prefix value.
			markUnknown()
			defer markUnknown()
		}
	}
	conditional = conditional || state.conditionalDepth > 0 || state.inEval
	// The words before the command name: body and condition openers,
	// declaration builtins, and NAME=value assignments -- the places a
	// mktemp path is assigned in this shell.
	for len(words) > 0 && (prefixWords[words[0]] || assigns(raws[0])) {
		switch words[0] {
		case "if":
			state.conditionalDepth++
			conditional = true
		case "while", "until":
			state.conditionalDepth++
			state.loops = append(state.loops, map[string]bool{})
			conditional = true
		case "{":
			// A function's body is not made conditional: what it writes
			// is poisoned (wrote), which is the stronger of the two.
			group := braceGroup{conditional: conditional, function: state.pendingFunction, effects: state.effects}
			state.pendingFunction = false
			if group.function {
				state.functionDepth++
			}
			if group.conditional {
				state.conditionalDepth++
			}
			state.braces = append(state.braces, group)
		case "then", "else", "elif", "do":
			conditional = true
		case "command":
			// -p only picks the PATH the name is looked up in; -v and -V
			// make it a query and stay, as a command name that runs nothing.
			if len(words) > 1 && words[1] == "-p" {
				words, raws = words[1:], raws[1:]
			}
		}
		if !child {
			if assignsMktemp(raws[0]) {
				return true
			}
			if declarationBuiltins[words[0]] {
				// A declaration builtin assigns every NAME=value operand in
				// this shell, after its options and plain names too: export
				// PATH t=$(mktemp), local -r t=$(mktemp) (review of the guard
				// branch: the loop had stopped at PATH and -r).
				for i, r := range raws[1:] {
					// Its operand is an assignment after expansion, so a quoted
					// one assigns too: export "t=$(mktemp)" (second review).
					if mktempValue.MatchString(shView(r)) {
						return true
					}
					state.remember(r, words[i+1], conditional)
				}
			}
		}
		words, raws = words[1:], raws[1:]
	}
	if child {
		return false
	}
	if len(words) == 0 {
		// NAME=value before a regular command is only in that command's
		// environment. An assignment without a command persists.
		for i, r := range allRaws {
			state.remember(r, allWords[i], conditional)
		}
		return false
	}
	switch words[0] {
	case "unset":
		names := words[1:]
		for len(names) > 0 && strings.HasPrefix(names[0], "-") {
			option := names[0]
			names = names[1:]
			if option == "--" {
				break
			}
			if option != "-v" {
				// -f unsets functions, not variables. An unrecognized option
				// may fail without changing the previous variable value.
				return false
			}
		}
		for _, name := range names {
			state.wrote(name)
			delete(state.vars, name)
			if conditional || state.poisoned[name] {
				state.unknown[name] = true
			} else {
				delete(state.unknown, name)
			}
		}
		return false
	case "read":
		// Every operand that can be a name: an option's argument that looks
		// like one is forgotten too, which costs nothing.
		for _, word := range words[1:] {
			if shellName.MatchString(word) {
				state.forget(word)
			}
		}
		return false
	case "printf":
		if len(words) > 2 && words[1] == "-v" && shellName.MatchString(words[2]) {
			state.forget(words[2])
		} else if len(words) > 1 && strings.HasPrefix(words[1], "-v") && shellName.MatchString(words[1][2:]) {
			state.forget(words[1][2:])
		}
		return false
	case "eval":
		words, raws = words[1:], raws[1:]
		if len(words) > 0 && words[0] == "--" {
			words, raws = words[1:], raws[1:]
		}
		state.effects++
		for i, raw := range raws {
			state.evaluated(words[i])
			if strings.Contains(words[i], "${!") {
				// Indirection chooses a variable dynamically; do not interpret
				// it as a harmless literal or assume the target is unset.
				return true
			}
			if strings.Contains(words[i], "$(") || strings.Contains(words[i], "`") {
				// What a command prints is not text this reader has.
				return true
			}
			if value, ok := state.variableWord(raw); ok {
				words[i] = value
			} else if state.unresolvedStoredVariable(words[i]) {
				// Concatenation and parameter operators are not evaluated by
				// this lint. They must not hide a remembered script from it.
				return true
			}
		}
		return state.readStored(words)
	case "trap":
		state.effects++
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
			if strings.ContainsAny(sig, "$`") || strings.EqualFold(sig, "EXIT") || strings.EqualFold(sig, "SIGEXIT") {
				return true
			}
			// EXIT by number, however many zeros spell it.
			if allDigitsWord(sig) && strings.Trim(sig, "0") == "" {
				return true
			}
		}
		return false
	}
	return state.variableCommandLeaks(raws)
}

// variableCommandLeaks reads a command whose name comes out of a variable
// this shell wrote -- $cleanup, "$dir/tool" -- as eval would read it: the
// value is the command, a trap in it a trap. That is more than the shell does
// with it (no keyword or assignment survives an expansion), so it errs loud.
// A name never written here is somebody's environment and is left alone.
func (state *shellState) variableCommandLeaks(raws []string) bool {
	name := shView(raws[0])
	state.evaluated(name)
	if !state.unresolvedStoredVariable(name) {
		return false
	}
	known := func(ref string) (string, bool) {
		value, ok := state.vars[strings.Trim(ref, "${}")]
		return value, ok
	}
	rest := plainReference.ReplaceAllStringFunc(name, func(ref string) string {
		if _, ok := known(ref); ok {
			return ""
		}
		return ref
	})
	if state.unresolvedStoredVariable(rest) {
		// An unknown value, or a parameter operator around a known one.
		return true
	}
	expanded := plainReference.ReplaceAllStringFunc(name, func(ref string) string {
		if value, ok := known(ref); ok {
			return value
		}
		return ref
	})
	// The arguments stay as written, quotes and all: sh -c '...' is still a
	// child's script.
	return state.readStored(append([]string{expanded}, raws[1:]...))
}

// readStored reads words, joined, as the program an eval runs: with the
// shell's variables and a scope of its own.
func (state *shellState) readStored(words []string) bool {
	// Bound total expanded code before allocating it. Even without
	// a cycle, one stored script can invoke the next twice.
	for _, word := range words {
		state.evalBytesLeft -= len(word) + 1
		if state.evalBytesLeft < 0 {
			return true
		}
	}
	script := strings.Join(words, " ")
	if state.evaluating[script] {
		return true
	}
	state.evaluating[script] = true
	defer delete(state.evaluating, script)
	saved, loops := state.shellScope, len(state.loops)
	state.shellScope = shellScope{inEval: true, functionDepth: saved.functionDepth, loopBase: loops}
	leaks := state.shellLeaks(script)
	state.shellScope = saved
	state.loops = state.loops[:loops]
	return leaks
}

// wrote records that a command set or unset name here.
func (state *shellState) wrote(name string) {
	state.effects++
	if state.deferred[name] {
		state.replayed = true
	}
	for _, loop := range state.loops {
		if loop[name] {
			state.replayed = true
		}
	}
	if state.functionDepth > 0 {
		state.poisoned[name] = true
	}
}

// forget records a write whose value this reader does not have.
func (state *shellState) forget(name string) {
	state.wrote(name)
	delete(state.vars, name)
	state.unknown[name] = true
}

// evaluated records the names a word hands to eval, or runs as a command,
// where the read will happen again later: in a loop, in a function body.
func (state *shellState) evaluated(word string) {
	for _, ref := range shellVariableReference.FindAllStringSubmatch(word, -1) {
		for _, loop := range state.loops {
			loop[ref[1]] = true
		}
		if state.functionDepth > 0 {
			state.deferred[ref[1]] = true
		}
	}
}

// remember records a statically known unconditional assignment. A branch
// may not execute, so its reassignment cannot erase a possibly unsafe value;
// NAME+=value depends on what the name held.
func (state *shellState) remember(raw, word string, conditional bool) {
	if !assigns(raw) {
		return
	}
	written, rawValue, _ := strings.Cut(raw, "=")
	_, value, _ := strings.Cut(word, "=")
	name := assignedName(raw)
	appends := written != name
	state.wrote(name)
	if conditional || appends || state.poisoned[name] {
		delete(state.vars, name)
		state.unknown[name] = true
	} else if expanded, ok := state.variableWord(rawValue); ok {
		state.vars[name] = expanded
		delete(state.unknown, name)
	} else if !strings.ContainsAny(blankSingleQuoted(rawValue), "$`") {
		state.vars[name] = value
		delete(state.unknown, name)
	} else {
		delete(state.vars, name)
		state.unknown[name] = true
	}
}

var shellVariableReference = regexp.MustCompile(`\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)`)

// plainReference is $NAME or ${NAME}, with no parameter operator.
var plainReference = regexp.MustCompile(`\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)`)

func (state *shellState) unresolvedStoredVariable(word string) bool {
	for _, ref := range shellVariableReference.FindAllStringSubmatch(word, -1) {
		if _, known := state.vars[ref[1]]; known || state.unknown[ref[1]] {
			return true
		}
	}
	return false
}

// variableWord resolves a direct $name or ${name} argument, optionally
// double quoted. Single quoting defers expansion to the shell eval starts.
func (state *shellState) variableWord(raw string) (string, bool) {
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	name, ok := strings.CutPrefix(raw, "$")
	if !ok {
		return "", false
	}
	if len(name) >= 2 && name[0] == '{' && name[len(name)-1] == '}' {
		name = name[1 : len(name)-1]
	}
	value, ok := state.vars[name]
	return value, ok
}

// shellWords is cmd's words after sh's quote removal, and beside each its
// text as written (raws), which is what tells an assignment from a quoted
// word that looks like one: '...' literal, "..."
// with \ escaping " \ $ and `, $'...' as a quoted word, \ outside quotes
// escaping the next byte. A redirection ends a word and takes its target
// with it: EXIT>/dev/null is the word EXIT.
func shellWords(cmd string) (words, raws []string) {
	var cur strings.Builder
	inWord, start := false, 0
	end := func(at int) {
		if inWord {
			words = append(words, cur.String())
			raws = append(raws, cmd[start:at])
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if !inWord {
			start = i
		}
		switch {
		case c == ' ' || c == '\t':
			end(i)
		case c == '>' || c == '<':
			// A leading fd number (2>) belongs to the redirection.
			if inWord && allDigitsWord(cur.String()) {
				cur.Reset()
				inWord = false
			}
			end(i)
			for i+1 < len(cmd) && strings.IndexByte("<>&|", cmd[i+1]) >= 0 {
				i++
			}
			for i+1 < len(cmd) && (cmd[i+1] == ' ' || cmd[i+1] == '\t') {
				i++
			}
			// The target is one word, quotes and all: >"$HOME/my log" is
			// one target, not two words (third review).
			for q := byte(0); i+1 < len(cmd) && (q != 0 || (cmd[i+1] != ' ' && cmd[i+1] != '\t')); {
				i++
				switch c := cmd[i]; {
				case q != 0 && c == q:
					q = 0
				case q == 0 && (c == '\'' || c == '"'):
					q = c
				case q != '\'' && c == '\\' && i+1 < len(cmd):
					i++
				}
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
		case startsSubstitution(cmd, i):
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
	end(len(cmd))
	return words, raws
}

func startsSubstitution(cmd string, i int) bool {
	return cmd[i] == '`' || (cmd[i] == '$' && i+1 < len(cmd) && (cmd[i+1] == '(' || cmd[i+1] == '{'))
}

// substitutionEnd is the index just past the substitution starting
// at cmd[i] -- $( ... ), ${ ... }, or ` ... ` -- or len(cmd) when it
// does not close on the line.
func substitutionEnd(cmd string, i int) int {
	if cmd[i] == '`' {
		if k := strings.IndexByte(cmd[i+1:], '`'); k >= 0 {
			return i + 1 + k + 1
		}
		return len(cmd)
	}
	open, close := cmd[i+1], byte(')')
	if open == '{' {
		close = '}'
	}
	depth, quote := 0, byte(0)
	for j := i + 1; j < len(cmd); j++ {
		switch c := cmd[j]; {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' {
				j++
			}
		case c == '\'' || c == '"':
			// $(echo ")") closes at the second ), not inside the quote
			// (second review).
			quote = c
		case c == '\\':
			j++
		case c == open:
			depth++
		case c == close:
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

func TestLeakGuardPhysicalWhitespaceAndEval(t *testing.T) {
	for _, tc := range []struct {
		script string
		leaks  bool
	}{
		{"    - |\n      echo safe\\ \n      trap 'echo cleanup' EXIT", true},
		{"    - |\n      echo safe\\\t\n      trap 'echo cleanup' EXIT", true},
		{"    - |\n      echo safe\\\n      trap 'echo cleanup' EXIT", false},
		{`cleanup_script='set -e; t=$(mktemp); trap "echo cleanup" EXIT'
eval "$cleanup_script"`, true},
		{`cleanup='trap "echo cleanup" EXIT'; eval "${cleanup}"`, true},
		{`cleanup='t=$(mktemp)'; eval $cleanup`, true},
		{`cleanup='trap "echo cleanup" TERM'; eval "$cleanup"`, false},
		{`cleanup='trap "echo cleanup" EXIT'; printf '%s' "$cleanup"`, false},
		{`cleanup='trap "echo cleanup" EXIT'; sh -c "$cleanup"`, false},
		{`cleanup='trap "echo cleanup" EXIT'; cleanup='echo ok'; eval "$cleanup"`, false},
		{`cleanup='trap "echo cleanup" EXIT'; unset cleanup; eval "$cleanup"`, false},
		{`cleanup='trap "echo cleanup" EXIT' env; eval "$cleanup"`, false},
		{`cleanup='trap "echo cleanup" EXIT' | cat; eval "$cleanup"`, false},
		{`true | cleanup='trap "echo cleanup" EXIT'; eval "$cleanup"`, true},
		{`true && cleanup='trap "echo cleanup" EXIT' & wait; eval "$cleanup"`, false},
		{`cleanup='trap "echo cleanup" EXIT'; eval "$cleanup" | cat; echo done`, false},
		{`cleanup='trap "echo cleanup" EXIT'; eval "$cleanup" & wait; echo done`, false},
		{`cleanup='trap "echo cleanup" EXIT'; eval "$cleanup" | cat; eval "$cleanup"`, true},
		{`t=$(mktemp | cat)`, true},
		{`case a in a|b) t=$(mktemp);; esac`, true},
		{`tag=${label#a|b} t=$(mktemp)`, true},
		{`echo $(printf '%s' "a | b"); trap 'echo cleanup' EXIT >|log`, true},
		{`msg=hello; script='eval printf "%s" "$msg"'; eval "$script" "$msg"`, false},
		{`cleanup='eval "$cleanup"'; eval "$cleanup"`, true},
	} {
		if got := leakedIntoJob.MatchString(tc.script); got != tc.leaks {
			t.Errorf("leaks = %v, want %v for %q", got, tc.leaks, tc.script)
		}
	}
}

func TestLeakGuardBoundsStoredEvalExpansion(t *testing.T) {
	// Each script evaluates the previous one twice. The input fits on a
	// page but would execute the leaf command over a billion times.
	var script strings.Builder
	name := "a"
	script.WriteString("a='echo ok'\n")
	for i := 0; i < 30; i++ {
		next := name + "a"
		script.WriteString(next + "='eval \"$" + name + "\"; eval \"$" + name + "\"'\n")
		name = next
	}
	script.WriteString("eval \"$" + name + "\"")
	if !leakedIntoJob.MatchString(script.String()) {
		t.Fatal("accepted an eval tree that exceeds the inspection budget")
	}
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
		// Review of the guard branch: a declaration builtin's later
		// operands, a comment after an operator, a double-quoted value.
		"    - export PATH t=$(mktemp)",
		"    - local -r t=$(mktemp)",
		"    - readonly -p t=$(mktemp)",
		"    - make;# note \\\n    - trap 'echo catch-me' EXIT",
		"    - make&&# note \\\n    - trap 'echo catch-me' EXIT",
		`    - t="$(mktemp)"`,
		`    - t=''"$(mktemp)"`,
		// Second review: a trap whose single-quoted handler spans lines, a
		// redirection's &, a #-word after $( ), a quoted export operand, a
		// quote inside $( ).
		"    - |\n      trap 'rm -f \"$t\"; \\\n        echo done' EXIT",
		`    - 2>&1 t=$(mktemp)`,
		`    - x=1 2>&1 t=$(mktemp)`,
		`    - echo $(date)#tag; trap 'x' EXIT`,
		`    - export "t=$(mktemp)"`,
		`    - x=$(echo ")") trap 'x' EXIT`,
		// Third review: a quoted redirection target with a blank, a comment
		// after a subshell's ).
		`    - >"$HOME/my log" t=$(mktemp)`,
		`    - > "a b" t=$(mktemp)`,
		"    - (make)# note \\\n    - trap 'echo catch-me' EXIT",
		// Fourth review: real leaks the word reading alone had let through.
		`    - ver="$(date "+%Y %m")" t=$(mktemp)`,
		`    - f() { t=$(mktemp); }; f`,
		`    - x=it\'s t=$(mktemp)'y'`,
		`    - case x in *) x=it\'s t=$(mktemp)'y';; esac`,
		`    - case x in *) y="it's" t=$(mktemp);; esac`,
		// Fifth review: quotes nested in a substitution, and $'...' (ash; dash has none).
		`    - v="$(echo "it's")" t=$(mktemp)`,
		`    - tag="$(echo a | tr "'" _)" t=$(mktemp)`,
		"    - v=\"`echo \"it's\"`\" t=$(mktemp)",
		`    - v=$'a\'b' t=$(mktemp)`,
		`    - case x in *) t=$(mktemp);; esac`,
		`    - echo $(case a in a) echo y;; esac)#x; trap "echo LEAK" EXIT`,
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

		// A quoted word is a command name, not an assignment, and a
		// single-quoted value is text.
		`    - "t=$(mktemp)" || true`,
		`    - t='$(mktemp)'`,
		`    - "x=1" trap 'echo cleanup' EXIT`,
		`    - export PATH`,
		// A README line that is one quoted word is a command of that name to
		// sh, not a trap: only a YAML value is unquoted as YAML.
		`"trap 'x' EXIT"`,
	} {
		if leakedIntoJob.MatchString(line) {
			t.Errorf("wrongly caught: %s", line)
		}
	}
}
