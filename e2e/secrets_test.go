//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/store"
)

// secrets tests run on separate server with --secrets.key enabled
const (
	secretsBaseURL  = "http://localhost:18081"
	secretsDBPath   = "/tmp/stash-e2e-secrets.db"
	secretsGitPath  = "/tmp/stash-e2e-secrets-git"
	secretsAuthFile = "e2e/testdata/auth-secrets.yml"
	secretsKey      = "e2e-test-secret-key-minimum-16-chars"
)

// startSecretsServer starts a separate server with secrets enabled
func startSecretsServer(t *testing.T) func() {
	t.Helper()

	// cleanup old data
	_ = os.Remove(secretsDBPath)
	_ = os.RemoveAll(secretsGitPath)

	cmd := exec.Command("/tmp/stash-e2e", "server",
		"--dbg",
		"--server.address=:18081",
		"--db="+secretsDBPath,
		"--auth.file="+secretsAuthFile,
		"--git.enabled",
		"--git.path="+secretsGitPath,
		"--secrets.key="+secretsKey,
	)
	cmd.Dir = ".."

	require.NoError(t, cmd.Start())
	require.NoError(t, waitForServer(secretsBaseURL+"/ping", 30*time.Second))

	return func() {
		_ = cmd.Process.Kill()
		_ = os.Remove(secretsDBPath)
		_ = os.RemoveAll(secretsGitPath)
	}
}

// ==================== Secrets Tests ====================

func TestSecrets_LockIconDisplayed(t *testing.T) {
	cleanup := startSecretsServer(t)
	defer cleanup()

	page := newPage(t)
	_, err := page.Goto(secretsBaseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill("admin"))
	require.NoError(t, page.Locator("#password").Fill("testpass"))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	waitVisible(t, page.Locator(`h1:has-text("Stash")`))

	// create a secret key
	secretKeyName := "secrets/e2e-test"
	require.NoError(t, page.Locator(`button:has-text("New Key")`).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	require.NoError(t, page.Locator(`input[name="key"]`).Fill(secretKeyName))
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill("secret value"))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// verify lock icon is displayed
	keyCell := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, secretKeyName))
	waitVisible(t, keyCell)

	lockIcon := keyCell.Locator(".lock-icon")
	visible, err := lockIcon.IsVisible()
	require.NoError(t, err)
	assert.True(t, visible, "lock icon should be displayed for secret keys")

	// cleanup - delete the key
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, secretKeyName))
	require.NoError(t, row.Locator(".btn-danger").Click())
	confirmModal := page.Locator("#confirm-modal")
	waitVisible(t, confirmModal)
	require.NoError(t, page.Locator("#confirm-delete-btn").Click())
	waitHidden(t, confirmModal)
}

func TestSecrets_RegularKeyNoLockIcon(t *testing.T) {
	cleanup := startSecretsServer(t)
	defer cleanup()

	page := newPage(t)
	_, err := page.Goto(secretsBaseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill("admin"))
	require.NoError(t, page.Locator("#password").Fill("testpass"))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	waitVisible(t, page.Locator(`h1:has-text("Stash")`))

	// create a regular key (not a secret)
	keyName := "e2e-regular/no-lock"
	require.NoError(t, page.Locator(`button:has-text("New Key")`).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	require.NoError(t, page.Locator(`input[name="key"]`).Fill(keyName))
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill("regular value"))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// verify no lock icon
	keyCell := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName))
	waitVisible(t, keyCell)

	lockIcon := keyCell.Locator(".lock-icon")
	visible, err := lockIcon.IsVisible()
	require.NoError(t, err)
	assert.False(t, visible, "lock icon should NOT be displayed for regular keys")

	// cleanup
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, keyName))
	require.NoError(t, row.Locator(".btn-danger").Click())
	confirmModal := page.Locator("#confirm-modal")
	waitVisible(t, confirmModal)
	require.NoError(t, page.Locator("#confirm-delete-btn").Click())
	waitHidden(t, confirmModal)
}

func TestSecrets_UserWithoutSecretsPermissionCannotSee(t *testing.T) {
	cleanup := startSecretsServer(t)
	defer cleanup()

	// create secret as admin
	adminPage := newPage(t)
	_, err := adminPage.Goto(secretsBaseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, adminPage.Locator("#username").Fill("admin"))
	require.NoError(t, adminPage.Locator("#password").Fill("testpass"))
	require.NoError(t, adminPage.Locator(`button[type="submit"]`).Click())
	waitVisible(t, adminPage.Locator(`h1:has-text("Stash")`))

	secretKeyName := "secrets/e2e-hidden"
	require.NoError(t, adminPage.Locator(`button:has-text("New Key")`).Click())
	modal := adminPage.Locator("#main-modal.active")
	waitVisible(t, modal)

	require.NoError(t, adminPage.Locator(`input[name="key"]`).Fill(secretKeyName))
	require.NoError(t, adminPage.Locator(`textarea[name="value"]`).Fill("hidden secret"))
	require.NoError(t, adminPage.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// verify admin can see it
	keyCell := adminPage.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, secretKeyName))
	waitVisible(t, keyCell)
	visible, err := keyCell.IsVisible()
	require.NoError(t, err)
	assert.True(t, visible, "admin should see the secret key")

	// login as user without secrets permission
	page := newPage(t)
	_, err = page.Goto(secretsBaseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill("noSecrets"))
	require.NoError(t, page.Locator("#password").Fill("testpass"))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	waitVisible(t, page.Locator(`h1:has-text("Stash")`))

	// wait for key list container to be visible (page stabilized)
	// note: when no keys visible, there's no table - just empty state in #keys-table div
	waitVisible(t, page.Locator("#keys-table"))

	// user without secrets permission should NOT see the secret key
	keyCellNoSecrets := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, secretKeyName))
	visible, err = keyCellNoSecrets.IsVisible()
	require.NoError(t, err)
	assert.False(t, visible, "user without secrets permission should NOT see secret keys")

	// cleanup as admin
	row := adminPage.Locator(fmt.Sprintf(`tr:has-text(%q)`, secretKeyName))
	require.NoError(t, row.Locator(".btn-danger").Click())
	confirmModal := adminPage.Locator("#confirm-modal")
	waitVisible(t, confirmModal)
	require.NoError(t, adminPage.Locator("#confirm-delete-btn").Click())
	waitHidden(t, confirmModal)
}

func TestSecrets_CardViewLockIcon(t *testing.T) {
	cleanup := startSecretsServer(t)
	defer cleanup()

	page := newPage(t)
	_, err := page.Goto(secretsBaseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill("admin"))
	require.NoError(t, page.Locator("#password").Fill("testpass"))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	waitVisible(t, page.Locator(`h1:has-text("Stash")`))

	// create a secret key
	secretKeyName := "secrets/e2e-card"
	require.NoError(t, page.Locator(`button:has-text("New Key")`).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	require.NoError(t, page.Locator(`input[name="key"]`).Fill(secretKeyName))
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill("secret for card view"))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// switch to card view
	require.NoError(t, page.Locator(`button[title="Toggle view mode"]`).Click())
	cardsContainer := page.Locator(".cards-container")
	waitVisible(t, cardsContainer)

	// verify lock icon in card view
	card := page.Locator(fmt.Sprintf(`.key-card:has-text(%q)`, secretKeyName))
	waitVisible(t, card)

	lockIcon := card.Locator(".lock-icon")
	visible, err := lockIcon.IsVisible()
	require.NoError(t, err)
	assert.True(t, visible, "lock icon should be displayed in card view for secret keys")

	// switch back to table view for cleanup
	require.NoError(t, page.Locator(`button[title="Toggle view mode"]`).Click())
	waitVisible(t, page.Locator("table"))

	// cleanup
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, secretKeyName))
	require.NoError(t, row.Locator(".btn-danger").Click())
	confirmModal := page.Locator("#confirm-modal")
	waitVisible(t, confirmModal)
	require.NoError(t, page.Locator("#confirm-delete-btn").Click())
	waitHidden(t, confirmModal)
}

func TestSecrets_FilterToggle(t *testing.T) {
	cleanup := startSecretsServer(t)
	defer cleanup()

	page := newPage(t)
	_, err := page.Goto(secretsBaseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill("admin"))
	require.NoError(t, page.Locator("#password").Fill("testpass"))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	waitVisible(t, page.Locator(`h1:has-text("Stash")`))

	// create a regular key
	regularKeyName := "regular/filter-test"
	require.NoError(t, page.Locator(`button:has-text("New Key")`).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)
	require.NoError(t, page.Locator(`input[name="key"]`).Fill(regularKeyName))
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill("regular value"))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// create a secret key
	secretKeyName := "secrets/filter-test"
	require.NoError(t, page.Locator(`button:has-text("New Key")`).Click())
	waitVisible(t, modal)
	require.NoError(t, page.Locator(`input[name="key"]`).Fill(secretKeyName))
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill("secret value"))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// verify both keys are visible (All filter - default)
	filterButton := page.Locator(".filter-button")
	waitVisible(t, filterButton)
	filterLabel := page.Locator("#filter-label")
	labelText, err := filterLabel.TextContent()
	require.NoError(t, err)
	assert.Equal(t, "All", labelText, "default filter should be All")

	regularCell := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, regularKeyName))
	secretCell := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, secretKeyName))
	waitVisible(t, regularCell)
	waitVisible(t, secretCell)

	// click filter to switch to "Secrets" mode
	require.NoError(t, filterButton.Click())
	assert.Eventually(t, func() bool {
		text, e := filterLabel.TextContent()
		return e == nil && text == "Secrets"
	}, 5*time.Second, 100*time.Millisecond, "filter should switch to Secrets")

	// verify only secret key is visible
	secretVisible, err := secretCell.IsVisible()
	require.NoError(t, err)
	assert.True(t, secretVisible, "secret key should be visible in Secrets filter")

	regularVisible, err := regularCell.IsVisible()
	require.NoError(t, err)
	assert.False(t, regularVisible, "regular key should NOT be visible in Secrets filter")

	// click filter to switch to "Keys" mode
	require.NoError(t, filterButton.Click())
	assert.Eventually(t, func() bool {
		text, e := filterLabel.TextContent()
		return e == nil && text == "Keys"
	}, 5*time.Second, 100*time.Millisecond, "filter should switch to Keys")

	// verify only regular key is visible
	regularVisible, err = regularCell.IsVisible()
	require.NoError(t, err)
	assert.True(t, regularVisible, "regular key should be visible in Keys filter")

	secretVisible, err = secretCell.IsVisible()
	require.NoError(t, err)
	assert.False(t, secretVisible, "secret key should NOT be visible in Keys filter")

	// click filter to switch back to "All" mode
	require.NoError(t, filterButton.Click())
	assert.Eventually(t, func() bool {
		text, e := filterLabel.TextContent()
		return e == nil && text == "All"
	}, 5*time.Second, 100*time.Millisecond, "filter should switch back to All")

	// verify both keys are visible again
	waitVisible(t, regularCell)
	waitVisible(t, secretCell)

	// cleanup - delete both keys
	for _, key := range []string{regularKeyName, secretKeyName} {
		row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, key))
		require.NoError(t, row.Locator(".btn-danger").Click())
		confirmModal := page.Locator("#confirm-modal")
		waitVisible(t, confirmModal)
		require.NoError(t, page.Locator("#confirm-delete-btn").Click())
		waitHidden(t, confirmModal)
		waitHidden(t, row)
	}
}

func TestSecrets_ScopedSecretsAccess(t *testing.T) {
	cleanup := startSecretsServer(t)
	defer cleanup()

	// create secrets as admin in different paths
	adminPage := newPage(t)
	_, err := adminPage.Goto(secretsBaseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, adminPage.Locator("#username").Fill("admin"))
	require.NoError(t, adminPage.Locator("#password").Fill("testpass"))
	require.NoError(t, adminPage.Locator(`button[type="submit"]`).Click())
	waitVisible(t, adminPage.Locator(`h1:has-text("Stash")`))

	// create secret in app/secrets/ (appSecrets user should see)
	appSecretKey := "app/secrets/e2e-scoped"
	require.NoError(t, adminPage.Locator(`button:has-text("New Key")`).Click())
	modal := adminPage.Locator("#main-modal.active")
	waitVisible(t, modal)
	require.NoError(t, adminPage.Locator(`input[name="key"]`).Fill(appSecretKey))
	require.NoError(t, adminPage.Locator(`textarea[name="value"]`).Fill("app secret"))
	require.NoError(t, adminPage.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// create secret in secrets/ (appSecrets user should NOT see)
	globalSecretKey := "secrets/e2e-global"
	require.NoError(t, adminPage.Locator(`button:has-text("New Key")`).Click())
	waitVisible(t, modal)
	require.NoError(t, adminPage.Locator(`input[name="key"]`).Fill(globalSecretKey))
	require.NoError(t, adminPage.Locator(`textarea[name="value"]`).Fill("global secret"))
	require.NoError(t, adminPage.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// login as appSecrets user
	page := newPage(t)
	_, err = page.Goto(secretsBaseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill("appSecrets"))
	require.NoError(t, page.Locator("#password").Fill("testpass"))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	waitVisible(t, page.Locator(`h1:has-text("Stash")`))

	// wait for table to load
	waitVisible(t, page.Locator("table"))

	// appSecrets should see app/secrets/e2e-scoped (may need a short wait for data)
	appKeyCell := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, appSecretKey))
	assert.Eventually(t, func() bool {
		vis, e := appKeyCell.IsVisible()
		return e == nil && vis
	}, 5*time.Second, 100*time.Millisecond, "appSecrets user should see app/secrets/* key")

	// appSecrets should NOT see secrets/e2e-global (check immediately - it should never appear)
	globalKeyCell := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, globalSecretKey))
	visible, err := globalKeyCell.IsVisible()
	require.NoError(t, err)
	assert.False(t, visible, "appSecrets user should NOT see secrets/* key")

	// cleanup as admin - reload page first to ensure fresh state
	_, err = adminPage.Goto(secretsBaseURL + "/")
	require.NoError(t, err)
	waitVisible(t, adminPage.Locator("table"))

	for _, key := range []string{appSecretKey, globalSecretKey} {
		row := adminPage.Locator(fmt.Sprintf(`tr:has-text(%q)`, key))
		deleteBtn := row.Locator(".btn-danger")
		vis, err := deleteBtn.IsVisible()
		if err != nil || !vis {
			continue // key might already be deleted or not visible
		}
		require.NoError(t, deleteBtn.Click())
		confirmModal := adminPage.Locator("#confirm-modal")
		waitVisible(t, confirmModal)
		require.NoError(t, adminPage.Locator("#confirm-delete-btn").Click())
		waitHidden(t, confirmModal)
		// wait for row to disappear before next iteration
		waitHidden(t, row)
	}
}

func TestSecrets_EditSecretValue(t *testing.T) {
	cleanup := startSecretsServer(t)
	defer cleanup()

	page := newPage(t)
	_, err := page.Goto(secretsBaseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill("admin"))
	require.NoError(t, page.Locator("#password").Fill("testpass"))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	waitVisible(t, page.Locator(`h1:has-text("Stash")`))

	// create a secret key
	secretKeyName := "secrets/e2e-edit-test"
	originalValue := "original-secret-value"
	require.NoError(t, page.Locator(`button:has-text("New Key")`).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	require.NoError(t, page.Locator(`input[name="key"]`).Fill(secretKeyName))
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill(originalValue))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// wait for key to appear
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, secretKeyName))
	waitVisible(t, row)

	// click edit button
	editBtn := row.Locator(".btn-edit")
	waitVisible(t, editBtn)
	require.NoError(t, editBtn.Click())
	waitVisible(t, modal)

	// verify original value is shown
	textarea := page.Locator(`textarea[name="value"]`)
	val, err := textarea.InputValue()
	require.NoError(t, err)
	assert.Equal(t, originalValue, val, "edit form should show original decrypted value")

	// update the value
	updatedValue := "updated-secret-value"
	require.NoError(t, textarea.Fill(updatedValue))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// verify update by clicking the key cell to open view modal
	keyCell := row.Locator("td.key-cell")
	require.NoError(t, keyCell.Click())
	waitVisible(t, modal)

	// check the displayed value contains updated value
	modalContent := page.Locator("#modal-content")
	text, err := modalContent.TextContent()
	require.NoError(t, err)
	assert.Contains(t, text, updatedValue, "view modal should show updated secret value")

	// close modal
	require.NoError(t, page.Keyboard().Press("Escape"))
	waitHidden(t, modal)

	// cleanup
	require.NoError(t, row.Locator(".btn-danger").Click())
	confirmModal := page.Locator("#confirm-modal")
	waitVisible(t, confirmModal)
	require.NoError(t, page.Locator("#confirm-delete-btn").Click())
	waitHidden(t, confirmModal)
}

func TestSecrets_History(t *testing.T) {
	cleanup := startSecretsServer(t)
	defer cleanup()

	page := newPage(t)
	_, err := page.Goto(secretsBaseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill("admin"))
	require.NoError(t, page.Locator("#password").Fill("testpass"))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	waitVisible(t, page.Locator(`h1:has-text("Stash")`))

	// create a secret key with initial value
	secretKeyName := "secrets/e2e-history-test"
	initialValue := "initial-secret"
	require.NoError(t, page.Locator(`button:has-text("New Key")`).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	require.NoError(t, page.Locator(`input[name="key"]`).Fill(secretKeyName))
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill(initialValue))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// wait for key to appear
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, secretKeyName))
	waitVisible(t, row)

	// update the secret to create history
	editBtn := row.Locator(".btn-edit")
	waitVisible(t, editBtn)
	require.NoError(t, editBtn.Click())
	waitVisible(t, modal)

	updatedValue := "updated-secret"
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill(updatedValue))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// open view modal by clicking the key cell
	keyCell := row.Locator("td.key-cell")
	require.NoError(t, keyCell.Click())
	waitVisible(t, modal)

	// click history button
	historyBtn := page.Locator(`button:has-text("History")`)
	waitVisible(t, historyBtn)
	require.NoError(t, historyBtn.Click())

	// wait for history table to load
	historyTable := page.Locator(".history-table")
	waitVisible(t, historyTable)

	// verify history shows multiple entries (at least 2 - create and update)
	historyEntries := page.Locator(".history-table tbody tr")
	count, err := historyEntries.Count()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 2, "should have at least 2 history entries (create + update)")

	// close modal
	require.NoError(t, page.Keyboard().Press("Escape"))
	waitHidden(t, modal)

	// cleanup
	require.NoError(t, row.Locator(".btn-danger").Click())
	confirmModal := page.Locator("#confirm-modal")
	waitVisible(t, confirmModal)
	require.NoError(t, page.Locator("#confirm-delete-btn").Click())
	waitHidden(t, confirmModal)
}

func TestZK_InSecretsPath(t *testing.T) {
	// ZK-encrypted values in secrets paths should show both lock and shield icons,
	// and edit button should be hidden (ZK takes precedence over server encryption)
	cleanup := startSecretsServer(t)
	defer cleanup()

	// create a valid ZK-encrypted value using ZKCrypto
	zk, err := store.NewZKCrypto([]byte("e2e-test-passphrase"))
	require.NoError(t, err)
	zkValueBytes, err := zk.Encrypt([]byte("my-api-key-value"))
	require.NoError(t, err)

	// create a ZK-encrypted key via API using token auth
	zkKey := "secrets/zk-api-key"
	zkValue := string(zkValueBytes)

	req, err := http.NewRequest(http.MethodPut, secretsBaseURL+"/kv/"+zkKey, strings.NewReader(zkValue))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer e2e-secrets-token-12345")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "should create ZK key via API")

	// login to UI
	page := newPage(t)
	_, err = page.Goto(secretsBaseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill("admin"))
	require.NoError(t, page.Locator("#password").Fill("testpass"))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	waitVisible(t, page.Locator(`h1:has-text("Stash")`))

	// wait for key to appear in table
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, zkKey))
	waitVisible(t, row)

	keyCell := row.Locator("td.key-cell")
	waitVisible(t, keyCell)

	// verify both icons are visible
	lockIcon := keyCell.Locator(".lock-icon")
	lockVisible, err := lockIcon.IsVisible()
	require.NoError(t, err)
	assert.True(t, lockVisible, "lock icon should be visible for secrets path")

	zkIcon := keyCell.Locator(".zk-lock-icon")
	zkVisible, err := zkIcon.IsVisible()
	require.NoError(t, err)
	assert.True(t, zkVisible, "ZK shield icon should be visible for ZK-encrypted value")

	// verify edit button is hidden (ZK values cannot be edited on server)
	editBtn := row.Locator(".btn-edit")
	editVisible, err := editBtn.IsVisible()
	require.NoError(t, err)
	assert.False(t, editVisible, "edit button should be hidden for ZK-encrypted values")

	// cleanup - delete via API
	req, err = http.NewRequest(http.MethodDelete, secretsBaseURL+"/kv/"+zkKey, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer e2e-secrets-token-12345")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "should delete ZK key via API")
}
