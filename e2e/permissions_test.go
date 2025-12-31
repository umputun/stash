//go:build e2e

package e2e

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermissions_AdminFullAccess(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-perm/admin-test"

	// create
	createKey(t, page, keyName, "admin value")

	// edit
	updateKey(t, page, keyName, "updated by admin")

	// delete
	deleteKey(t, page, keyName)

	visible, err := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).IsVisible()
	require.NoError(t, err)
	assert.False(t, visible)
}

func TestPermissions_ReadonlyCannotCreate(t *testing.T) {
	page := newPage(t)
	login(t, page, "readonly", "testpass")

	visible, err := page.Locator(`button:has-text("New Key")`).IsVisible()
	require.NoError(t, err)
	assert.False(t, visible, "readonly user should not see New Key button")
}

func TestPermissions_ReadonlyCannotEditDelete(t *testing.T) {
	// create key as admin first
	adminPage := newPage(t)
	login(t, adminPage, "admin", "testpass")

	keyName := "e2e-perm/readonly-check"
	createKey(t, adminPage, keyName, "test")

	// check as readonly
	page := newPage(t)
	login(t, page, "readonly", "testpass")
	keyCell := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName))
	waitVisible(t, keyCell)

	// key should be visible
	visible, err := keyCell.IsVisible()
	require.NoError(t, err)
	assert.True(t, visible, "readonly user should see the key")

	// but no edit/delete buttons
	editVisible, err := page.Locator(".btn-edit").First().IsVisible()
	require.NoError(t, err)
	deleteVisible, err := page.Locator(".btn-danger").First().IsVisible()
	require.NoError(t, err)
	assert.False(t, editVisible, "readonly user should not see edit buttons")
	assert.False(t, deleteVisible, "readonly user should not see delete buttons")

	// cleanup
	deleteKey(t, adminPage, keyName)
}

func TestPermissions_ScopedUserPrefix(t *testing.T) {
	// create keys as admin
	adminPage := newPage(t)
	login(t, adminPage, "admin", "testpass")

	outsideKey := "e2e-perm/outside"
	insideKey := "app/e2e-perm-test"

	createKey(t, adminPage, outsideKey, "outside scope")
	createKey(t, adminPage, insideKey, "inside scope")

	// check as scoped user (only sees app/* prefix)
	page := newPage(t)
	login(t, page, "scoped", "testpass")
	insideCell := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, insideKey))
	waitVisible(t, insideCell)

	// should see app/* key
	insideVisible, err := insideCell.IsVisible()
	require.NoError(t, err)
	assert.True(t, insideVisible, "scoped user should see app/* key")

	// should not see key outside prefix
	outsideVisible, err := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, outsideKey)).IsVisible()
	require.NoError(t, err)
	assert.False(t, outsideVisible, "scoped user should not see key outside app/* prefix")

	// cleanup
	deleteKey(t, adminPage, outsideKey)
	deleteKey(t, adminPage, insideKey)
}
