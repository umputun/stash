package web

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHighlighter_Code(t *testing.T) {
	h := NewHighlighter()

	t.Run("text format returns escaped pre tag", func(t *testing.T) {
		code := `{"key": "value"}`
		result := h.Code(code, "text")
		assert.Equal(t, `<pre>{&#34;key&#34;: &#34;value&#34;}</pre>`, string(result))
	})

	t.Run("empty format returns escaped pre tag", func(t *testing.T) {
		code := `<script>alert("xss")</script>`
		result := h.Code(code, "")
		assert.Contains(t, string(result), "&lt;script&gt;")
		assert.NotContains(t, string(result), "<script>")
	})

	t.Run("json format produces highlighted output", func(t *testing.T) {
		code := `{"name": "test", "value": 123}`
		result := h.Code(code, "json")
		// should contain chroma class markers
		assert.Contains(t, string(result), "chroma")
		// should contain the actual content
		assert.Contains(t, string(result), "name")
		assert.Contains(t, string(result), "test")
	})

	t.Run("yaml format produces highlighted output", func(t *testing.T) {
		code := "name: test\nvalue: 123"
		result := h.Code(code, "yaml")
		assert.Contains(t, string(result), "chroma")
		assert.Contains(t, string(result), "name")
	})

	t.Run("xml format produces highlighted output", func(t *testing.T) {
		code := `<root><item>value</item></root>`
		result := h.Code(code, "xml")
		assert.Contains(t, string(result), "chroma")
		assert.Contains(t, string(result), "root")
	})

	t.Run("toml format produces highlighted output", func(t *testing.T) {
		code := "[section]\nkey = \"value\""
		result := h.Code(code, "toml")
		assert.Contains(t, string(result), "chroma")
		assert.Contains(t, string(result), "section")
	})

	t.Run("ini format produces highlighted output", func(t *testing.T) {
		code := "[section]\nkey = value"
		result := h.Code(code, "ini")
		assert.Contains(t, string(result), "chroma")
		assert.Contains(t, string(result), "section")
	})

	t.Run("shell format produces highlighted output", func(t *testing.T) {
		code := "echo $HOME && ls -la"
		result := h.Code(code, "shell")
		assert.Contains(t, string(result), "chroma")
		assert.Contains(t, string(result), "echo")
	})

	t.Run("unknown format returns escaped pre tag", func(t *testing.T) {
		code := "some code"
		result := h.Code(code, "unknown")
		assert.Equal(t, "<pre>some code</pre>", string(result))
	})

	t.Run("special characters are escaped in text mode", func(t *testing.T) {
		code := `<div class="test">&amp;</div>`
		result := h.Code(code, "text")
		// should not contain unescaped HTML
		assert.NotContains(t, string(result), `<div`)
		assert.Contains(t, string(result), "&lt;div")
		assert.Contains(t, string(result), "&amp;amp;")
	})

	t.Run("multiline json is highlighted", func(t *testing.T) {
		code := `{
  "name": "test",
  "items": [1, 2, 3]
}`
		result := h.Code(code, "json")
		assert.Contains(t, string(result), "chroma")
		assert.Contains(t, string(result), "items")
	})
}
