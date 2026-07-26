package shell

import (
	"strings"
	"unicode"
)

// Pipeline is one command line decomposed into its stages and the operator
// that joins it to whatever came next.
type Pipeline struct {
	Stages []Stage
	// Next is the operator connecting this pipeline to the following one:
	// ";", "&&", "||", or "" at end of line.
	Next string
	// Background is true when the pipeline was terminated with "&".
	Background bool
}

// Stage is a single command within a pipeline, with its redirections split out.
type Stage struct {
	Argv []string

	// RedirectOut / RedirectAppend hold the target of > and >>. Both empty
	// means no output redirection.
	RedirectOut    string
	RedirectAppend string
	RedirectIn     string

	// Heredoc content, when the stage used <<EOF style input.
	Heredoc string
}

// Parse splits a raw command line into pipelines. It is deliberately forgiving:
// the goal is to recover enough structure for feature extraction and for the
// emulator to respond plausibly, not to be a conformant POSIX shell. Anything
// it cannot parse still reaches the collector as a raw line.
func Parse(line string) []Pipeline {
	tokens := tokenize(line)
	if len(tokens) == 0 {
		return nil
	}

	var pipelines []Pipeline
	cur := Pipeline{}
	stage := Stage{}
	pendingRedirect := ""

	flushStage := func() {
		if len(stage.Argv) > 0 || stage.RedirectOut != "" || stage.RedirectAppend != "" {
			cur.Stages = append(cur.Stages, stage)
		}
		stage = Stage{}
	}
	flushPipeline := func(op string) {
		flushStage()
		if len(cur.Stages) > 0 {
			cur.Next = op
			pipelines = append(pipelines, cur)
		}
		cur = Pipeline{}
	}

	for _, t := range tokens {
		if pendingRedirect != "" {
			switch pendingRedirect {
			case ">":
				stage.RedirectOut = t.text
			case ">>":
				stage.RedirectAppend = t.text
			case "<":
				stage.RedirectIn = t.text
			}
			pendingRedirect = ""
			continue
		}

		if !t.quoted {
			switch t.text {
			case "|":
				flushStage()
				continue
			case ";", "\n":
				flushPipeline(";")
				continue
			case "&&":
				flushPipeline("&&")
				continue
			case "||":
				flushPipeline("||")
				continue
			case "&":
				cur.Background = true
				flushPipeline(";")
				continue
			case ">", ">>", "<":
				pendingRedirect = t.text
				continue
			}
		}
		stage.Argv = append(stage.Argv, t.text)
	}
	flushPipeline("")

	return pipelines
}

type token struct {
	text   string
	quoted bool
}

// tokenize splits on whitespace while honouring single quotes, double quotes,
// backslash escapes, and the shell operators. Unterminated quotes are treated
// as terminating at end of line, which is what a real shell would prompt about
// but which we accept silently -- bots emit malformed lines constantly and
// hanging on a PS2 prompt loses the session.
func tokenize(s string) []token {
	var out []token
	var cur strings.Builder
	curQuoted := false
	hasCur := false

	emit := func() {
		if hasCur {
			out = append(out, token{text: cur.String(), quoted: curQuoted})
			cur.Reset()
			curQuoted = false
			hasCur = false
		}
	}

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		switch {
		case c == '\\' && i+1 < len(runes):
			i++
			cur.WriteRune(runes[i])
			hasCur = true

		case c == '\'':
			hasCur = true
			curQuoted = true
			i++
			for i < len(runes) && runes[i] != '\'' {
				cur.WriteRune(runes[i])
				i++
			}

		case c == '"':
			hasCur = true
			curQuoted = true
			i++
			for i < len(runes) && runes[i] != '"' {
				if runes[i] == '\\' && i+1 < len(runes) {
					i++
				}
				cur.WriteRune(runes[i])
				i++
			}

		case unicode.IsSpace(c):
			emit()

		case c == '|' || c == '&':
			emit()
			if i+1 < len(runes) && runes[i+1] == c {
				out = append(out, token{text: string([]rune{c, c})})
				i++
			} else {
				out = append(out, token{text: string(c)})
			}

		case c == ';':
			emit()
			out = append(out, token{text: ";"})

		case c == '>':
			emit()
			if i+1 < len(runes) && runes[i+1] == '>' {
				out = append(out, token{text: ">>"})
				i++
			} else {
				out = append(out, token{text: ">"})
			}

		case c == '<':
			emit()
			out = append(out, token{text: "<"})

		default:
			cur.WriteRune(c)
			hasCur = true
		}
	}
	emit()
	return out
}

// ExtractURLs pulls fetchable references out of a command line. This is the
// input to ArtifactReference events. The node records these and never opens a
// connection to them -- see design doc section 4.2.
func ExtractURLs(argv []string) []string {
	var urls []string
	seen := map[string]bool{}
	for _, a := range argv {
		for _, cand := range urlCandidates(a) {
			if !seen[cand] {
				seen[cand] = true
				urls = append(urls, cand)
			}
		}
	}
	return urls
}

func urlCandidates(s string) []string {
	var out []string
	lower := strings.ToLower(s)
	for _, scheme := range []string{"http://", "https://", "ftp://", "tftp://"} {
		idx := 0
		for {
			i := strings.Index(lower[idx:], scheme)
			if i < 0 {
				break
			}
			start := idx + i

			// Guard against one scheme being a suffix of another: "tftp://x"
			// contains "ftp://x" at offset 1, and without this check a single
			// TFTP loader URL would be reported as two distinct artifacts.
			if start > 0 && isSchemeChar(lower[start-1]) {
				idx = start + len(scheme)
				continue
			}

			end := start
			for end < len(s) && !isURLTerminator(rune(s[end])) {
				end++
			}
			out = append(out, s[start:end])
			idx = end
			if idx >= len(lower) {
				break
			}
		}
	}
	return out
}

// isSchemeChar reports whether b may appear inside a URL scheme name (RFC 3986
// allows letters, digits, '+', '-' and '.').
func isSchemeChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '-' || b == '.'
}

func isURLTerminator(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '"', '\'', ';', '|', '&', '>', '<', '`':
		return true
	}
	return false
}
