//go:build e2e

package e2e

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistory_ShowsCommits(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-history/commits-test"
	createKey(t, page, keyName, "version 1")
	updateKey(t, page, keyName, "version 2")
	updateKey(t, page, keyName, "version 3")

	modal := viewKey(t, page, keyName)

	// click history button
	require.NoError(t, page.Locator(`button:has-text("History")`).Click())
	historyTable := page.Locator(".history-table")
	waitVisible(t, historyTable)

	// should see history table
	visible, err := historyTable.IsVisible()
	require.NoError(t, err)
	assert.True(t, visible, "history table should be visible")

	// close and cleanup
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)
	deleteKey(t, page, keyName)
}

func TestHistory_ViewSpecificRevision(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-history/revision-test"
	initialValue := "initial value"
	createKey(t, page, keyName, initialValue)
	updateKey(t, page, keyName, "updated value")

	modal := viewKey(t, page, keyName)

	// click history
	require.NoError(t, page.Locator(`button:has-text("History")`).Click())
	historyTable := page.Locator(".history-table")
	waitVisible(t, historyTable)

	// click on oldest revision (last row)
	rows := page.Locator(".history-table tbody tr")
	require.NoError(t, rows.Last().Locator("td").First().Click())
	// wait for revision content to load
	valueContent := page.Locator(".value-content")
	waitVisible(t, valueContent)

	// verify old value shown
	text, err := valueContent.TextContent()
	require.NoError(t, err)
	assert.Contains(t, text, initialValue)

	// cleanup
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)
	deleteKey(t, page, keyName)
}

func TestHistory_RestoreRevision(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-history/restore-test"
	originalValue := "original to restore"
	createKey(t, page, keyName, originalValue)
	updateKey(t, page, keyName, "new value")

	modal := viewKey(t, page, keyName)

	// click history
	require.NoError(t, page.Locator(`button:has-text("History")`).Click())
	historyTable := page.Locator(".history-table")
	waitVisible(t, historyTable)

	// click restore on oldest revision
	require.NoError(t, page.Locator(`button:has-text("Restore")`).Last().Click())
	// wait for modal to close after restore
	waitHidden(t, modal)

	// reload and verify restored
	_, err := page.Goto(baseURL + "/")
	require.NoError(t, err)
	keyCell := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName))
	waitVisible(t, keyCell)

	require.NoError(t, keyCell.Click())
	waitVisible(t, modal)
	valueContent := page.Locator(".value-content")
	waitVisible(t, valueContent)

	text, err := valueContent.TextContent()
	require.NoError(t, err)
	assert.Contains(t, text, originalValue)

	// cleanup
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)
	deleteKey(t, page, keyName)
}
