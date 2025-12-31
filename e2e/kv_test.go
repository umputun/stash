//go:build e2e

package e2e

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKV_CreateKey(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-crud/create-test"
	createKey(t, page, keyName, "test value")

	visible, err := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).IsVisible()
	require.NoError(t, err)
	assert.True(t, visible, "created key should be visible")

	deleteKey(t, page, keyName)
}

func TestKV_ViewKey(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-crud/view-test"
	keyValue := "value to view"
	createKey(t, page, keyName, keyValue)

	modal := viewKey(t, page, keyName)
	valueContent := page.Locator(".value-content")
	waitVisible(t, valueContent)

	// verify value
	text, err := valueContent.TextContent()
	require.NoError(t, err)
	assert.Contains(t, text, keyValue)

	// close and cleanup
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)
	deleteKey(t, page, keyName)
}

func TestKV_EditKey(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-crud/edit-test"
	createKey(t, page, keyName, "original value")

	// click edit
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, keyName))
	editBtn := row.Locator(".btn-edit")
	waitVisible(t, editBtn) // ensure button is ready after HTMX swap
	require.NoError(t, editBtn.Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	// update value
	newValue := "updated value"
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill(newValue))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// verify by viewing
	modal = viewKey(t, page, keyName)
	valueContent := page.Locator(".value-content")
	waitVisible(t, valueContent)

	text, err := valueContent.TextContent()
	require.NoError(t, err)
	assert.Contains(t, text, newValue)

	// cleanup
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)
	deleteKey(t, page, keyName)
}

func TestKV_DeleteKey(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-crud/delete-test"
	createKey(t, page, keyName, "to be deleted")

	deleteKey(t, page, keyName)

	visible, err := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).IsVisible()
	require.NoError(t, err)
	assert.False(t, visible, "deleted key should not be visible")
}

func TestKV_CreateKeyWithSlashes(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-crud/nested/deep/key"
	createKey(t, page, keyName, "nested value")

	visible, err := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).IsVisible()
	require.NoError(t, err)
	assert.True(t, visible, "nested key should be visible")

	deleteKey(t, page, keyName)
}
