package web

import (
	"bytes"
	"html"
	"html/template"
	"strings"

	"github.com/alecthomas/chroma/v2"
	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
)

// Highlighter provides syntax highlighting for code.
type Highlighter struct{}

// NewHighlighter creates a new Highlighter instance.
func NewHighlighter() *Highlighter {
	return &Highlighter{}
}

// Code applies syntax highlighting to code based on format.
// returns HTML-safe highlighted code or plain escaped text if format is "text" or highlighting fails.
func (h *Highlighter) Code(code, format string) template.HTML {
	if format == "" || format == "text" {
		return template.HTML("<pre>" + html.EscapeString(code) + "</pre>") //nolint:gosec // escaped
	}

	lexer := lexers.Get(strings.ToUpper(format))
	if lexer == nil {
		return template.HTML("<pre>" + html.EscapeString(code) + "</pre>") //nolint:gosec // escaped
	}
	lexer = chroma.Coalesce(lexer)

	// use CSS classes for theme-aware styling
	formatter := chromahtml.New(
		chromahtml.WithClasses(true),
		chromahtml.PreventSurroundingPre(false),
		chromahtml.WithLineNumbers(false),
	)

	iterator, err := lexer.Tokenise(nil, code)
	if err != nil {
		return template.HTML("<pre>" + html.EscapeString(code) + "</pre>") //nolint:gosec // escaped
	}

	var buf bytes.Buffer
	// use a minimal style since we're using CSS classes
	style := styles.Get("monokailight")
	if style == nil {
		style = styles.Fallback
	}

	if err := formatter.Format(&buf, style, iterator); err != nil {
		return template.HTML("<pre>" + html.EscapeString(code) + "</pre>") //nolint:gosec // escaped
	}

	return template.HTML(buf.String()) //nolint:gosec // chroma output is safe
}
