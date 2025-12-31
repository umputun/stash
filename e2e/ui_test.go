//go:build e2e

package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUI_ThemeToggle(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// get initial theme
	initialTheme, err := page.Locator("html").GetAttribute("data-theme")
	require.NoError(t, err)

	require.NoError(t, page.Locator(`button[title="Toggle theme"]`).Click())
	// wait for theme attribute to change
	assert.Eventually(t, func() bool {
		th, e := page.Locator("html").GetAttribute("data-theme")
		return e == nil && th != initialTheme
	}, 5*time.Second, 100*time.Millisecond, "theme should change")

	theme, err := page.Locator("html").GetAttribute("data-theme")
	require.NoError(t, err)
	assert.NotEmpty(t, theme)
}

func TestUI_DarkThemeCRUD(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// ensure dark theme is active (toggle until we get dark)
	for range 3 {
		theme, err := page.Locator("html").GetAttribute("data-theme")
		require.NoError(t, err)
		if theme == "dark" {
			break
		}
		require.NoError(t, page.Locator(`button[title="Toggle theme"]`).Click())
		assert.Eventually(t, func() bool {
			th, e := page.Locator("html").GetAttribute("data-theme")
			return e == nil && th != theme
		}, 5*time.Second, 100*time.Millisecond)
	}

	// verify dark theme is active
	theme, err := page.Locator("html").GetAttribute("data-theme")
	require.NoError(t, err)
	assert.Equal(t, "dark", theme, "dark theme should be active")

	// create key in dark mode
	keyName := "e2e-ui/dark-theme-test"
	keyValue := "dark mode value"
	createKey(t, page, keyName, keyValue)

	// view key in dark mode
	modal := viewKey(t, page, keyName)
	valueContent := page.Locator(".value-content")
	waitVisible(t, valueContent)

	text, err := valueContent.TextContent()
	require.NoError(t, err)
	assert.Contains(t, text, keyValue)

	// close modal
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)

	// edit key in dark mode
	updatedValue := "updated in dark mode"
	updateKey(t, page, keyName, updatedValue)

	// verify edit worked
	viewKey(t, page, keyName)
	waitVisible(t, valueContent)

	text, err = valueContent.TextContent()
	require.NoError(t, err)
	assert.Contains(t, text, updatedValue)

	// close and delete
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)
	deleteKey(t, page, keyName)

	// verify deleted
	visible, err := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).IsVisible()
	require.NoError(t, err)
	assert.False(t, visible, "key should be deleted")
}

func TestUI_ViewModeToggle(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-ui/viewmode"
	createKey(t, page, keyName, "test")

	// toggle to cards
	require.NoError(t, page.Locator(`button[title="Toggle view mode"]`).Click())
	cardsContainer := page.Locator(".cards-container")
	waitVisible(t, cardsContainer)

	visible, err := cardsContainer.IsVisible()
	require.NoError(t, err)
	assert.True(t, visible, "cards container should be visible")

	// toggle back to table
	require.NoError(t, page.Locator(`button[title="Toggle view mode"]`).Click())
	waitVisible(t, page.Locator("table"))

	deleteKey(t, page, keyName)
}

func TestUI_SortCycles(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// get initial sort label
	sortBtn := page.Locator(".sort-button")
	initialText, err := sortBtn.TextContent()
	require.NoError(t, err)

	// click sort button and wait for label to change
	require.NoError(t, sortBtn.Click())
	assert.Eventually(t, func() bool {
		txt, e := sortBtn.TextContent()
		return e == nil && txt != initialText
	}, 5*time.Second, 100*time.Millisecond, "sort label should change")
}

func TestUI_FormatSelector(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// open new key form
	require.NoError(t, page.Locator(`button:has-text("New Key")`).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	// check format options exist
	options, err := page.Locator(`select[name="format"] option`).All()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(options), 5, "should have at least 5 format options")

	// close
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)
}

func TestUI_SyntaxHighlighting(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-ui/highlight"
	jsonValue := `{"key": "value"}`
	createKeyWithFormat(t, page, keyName, jsonValue, "json")

	modal := viewKey(t, page, keyName)
	highlightedCode := page.Locator(".highlighted-code")
	waitVisible(t, highlightedCode)

	// should have highlighted code
	highlighted, err := highlightedCode.IsVisible()
	require.NoError(t, err)
	assert.True(t, highlighted, "should have syntax highlighting for JSON")

	// cleanup
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)
	deleteKey(t, page, keyName)
}

func TestUI_SecretsNotConfiguredError(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// try to create a key with "secrets" in path when --secrets.key is not configured
	require.NoError(t, page.Locator(`button:has-text("New Key")`).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	require.NoError(t, page.Locator(`input[name="key"]`).Fill("secrets/test-key"))
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill("test value"))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())

	// should show error message in form
	errorMsg := page.Locator("#form-error")
	waitVisible(t, errorMsg)

	errorText, err := errorMsg.TextContent()
	require.NoError(t, err)
	assert.Contains(t, errorText, "Secrets not configured", "should show secrets not configured error")

	// close modal
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)
}
