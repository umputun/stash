//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/store"
)

const apiToken = "e2e-admin-token-12345"

// createValidZKValue creates a valid ZK-encrypted value using ZKCrypto
func createValidZKValue(t *testing.T, plaintext string) string {
	t.Helper()
	zk, err := store.NewZKCrypto([]byte("e2e-test-passphrase"))
	require.NoError(t, err)
	encrypted, err := zk.Encrypt([]byte(plaintext))
	require.NoError(t, err)
	return string(encrypted)
}

// createZKKeyViaAPI creates a ZK-encrypted key via API (simulates client-side encryption)
func createZKKeyViaAPI(t *testing.T, key, zkValue string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, baseURL+"/kv/"+key, strings.NewReader(zkValue))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// createKeyViaAPI creates a regular key via API (for comparison tests)
func createKeyViaAPI(t *testing.T, key, value string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, baseURL+"/kv/"+key, strings.NewReader(value))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// deleteKeyViaAPI deletes a key via API
func deleteKeyViaAPI(t *testing.T, key string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, baseURL+"/kv/"+key, http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
}

func TestZK_ShowsDistinctIcon(t *testing.T) {
	// create ZK-encrypted key via API (with $ZK$ prefix)
	keyName := "e2e-zk/icon-test"
	zkValue := createValidZKValue(t, "test-encrypted-value")
	createZKKeyViaAPI(t, keyName, zkValue)
	defer deleteKeyViaAPI(t, keyName)

	// create regular key for comparison
	regularKeyName := "e2e-zk/regular-icon-test"
	createKeyViaAPI(t, regularKeyName, "regular value")
	defer deleteKeyViaAPI(t, regularKeyName)

	page := newPage(t)
	login(t, page, "admin", "testpass")

	// find the row with ZK key
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, keyName))
	waitVisible(t, row)

	// should have ZK lock icon (green shield)
	zkIcon := row.Locator(".zk-lock-icon")
	visible, err := zkIcon.IsVisible()
	require.NoError(t, err)
	assert.True(t, visible, "ZK-encrypted key should show lock icon")

	// regular key should NOT have ZK icon
	regularRow := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, regularKeyName))
	waitVisible(t, regularRow)
	regularZkIcon := regularRow.Locator(".zk-lock-icon")
	regularIconVisible, err := regularZkIcon.IsVisible()
	require.NoError(t, err)
	assert.False(t, regularIconVisible, "regular key should NOT show ZK lock icon")
}

func TestZK_EditButtonHidden(t *testing.T) {
	// create ZK-encrypted key via API
	keyName := "e2e-zk/edit-hidden-test"
	zkValue := createValidZKValue(t, "edit-hidden-test-value")
	createZKKeyViaAPI(t, keyName, zkValue)
	defer deleteKeyViaAPI(t, keyName)

	// create regular key for comparison
	regularKeyName := "e2e-zk/regular-edit-test"
	createKeyViaAPI(t, regularKeyName, "regular value")
	defer deleteKeyViaAPI(t, regularKeyName)

	page := newPage(t)
	login(t, page, "admin", "testpass")

	// find the row with ZK key
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, keyName))
	waitVisible(t, row)

	// edit button should NOT be visible for ZK-encrypted keys
	editBtn := row.Locator(".btn-edit")
	visible, err := editBtn.IsVisible()
	require.NoError(t, err)
	assert.False(t, visible, "edit button should be hidden for ZK-encrypted keys")

	// delete button should still be visible
	deleteBtn := row.Locator(".btn-danger")
	deleteVisible, err := deleteBtn.IsVisible()
	require.NoError(t, err)
	assert.True(t, deleteVisible, "delete button should still be visible")

	// regular key should have edit button visible
	regularRow := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, regularKeyName))
	waitVisible(t, regularRow)
	regularEditBtn := regularRow.Locator(".btn-edit")
	regularEditVisible, err := regularEditBtn.IsVisible()
	require.NoError(t, err)
	assert.True(t, regularEditVisible, "regular key should have edit button visible")
}

func TestZK_ViewModalShowsBadge(t *testing.T) {
	// create ZK-encrypted key via API with unique timestamp-based name
	keyName := fmt.Sprintf("e2e-zk/badge-test-%d", time.Now().UnixNano())
	zkValue := createValidZKValue(t, "badge-test-value")
	createZKKeyViaAPI(t, keyName, zkValue)
	defer deleteKeyViaAPI(t, keyName)

	page := newPage(t)
	login(t, page, "admin", "testpass")

	// click the ZK key to view - use viewKeyByText for ZK keys with trailing icon whitespace
	modal := viewKeyByText(t, page, keyName)

	// should show ZK badge in modal header
	zkBadge := page.Locator(".zk-badge")
	waitVisible(t, zkBadge)

	badgeText, err := zkBadge.TextContent()
	require.NoError(t, err)
	assert.Contains(t, badgeText, "Zero-Knowledge Encrypted")

	// edit button should NOT be visible in modal footer
	editBtn := modal.Locator(`button:has-text("Edit")`)
	editVisible, err := editBtn.IsVisible()
	require.NoError(t, err)
	assert.False(t, editVisible, "edit button should be hidden in modal for ZK-encrypted keys")

	// close modal
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)
}
