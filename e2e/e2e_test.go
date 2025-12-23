//go:build e2e

package e2e

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	baseURL     = "http://localhost:18080"
	testDBPath  = "/tmp/stash-e2e-pw.db"
	testGitPath = "/tmp/stash-e2e-pw-git"
	authFile    = "e2e/testdata/auth.yml"
)

var (
	serverCmd *exec.Cmd
	pw        *playwright.Playwright
	browser   playwright.Browser // single browser instance, reused across tests
)

// TestMain sets up and tears down the test server and playwright
func TestMain(m *testing.M) {
	// cleanup old data
	_ = os.Remove(testDBPath)
	_ = os.RemoveAll(testGitPath)

	// build the binary
	build := exec.Command("go", "build", "-o", "/tmp/stash-e2e", "./app")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		log.Fatalf("failed to build: %v\n%s", err, out)
	}

	// start the server
	serverCmd = exec.Command("/tmp/stash-e2e", "server",
		"--dbg",
		"--server.address=:18080",
		"--db="+testDBPath,
		"--auth.file="+authFile,
		"--git.enabled",
		"--git.path="+testGitPath,
	)
	serverCmd.Dir = ".."
	if err := serverCmd.Start(); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}

	// wait for server to be ready
	if err := waitForServer(baseURL+"/ping", 30*time.Second); err != nil {
		_ = serverCmd.Process.Kill()
		log.Fatalf("server not ready: %v", err)
	}

	// install playwright browsers if needed
	if err := playwright.Install(&playwright.RunOptions{Browsers: []string{"chromium"}}); err != nil {
		_ = serverCmd.Process.Kill()
		log.Fatalf("failed to install playwright: %v", err)
	}

	// start playwright
	var err error
	pw, err = playwright.Run()
	if err != nil {
		_ = serverCmd.Process.Kill()
		log.Fatalf("failed to start playwright: %v", err)
	}

	// launch browser once (reused across all tests via contexts)
	headless := os.Getenv("E2E_HEADLESS") != "false"
	var slowMo float64
	if !headless {
		slowMo = 50 // slow down visible browser for easier observation
	}
	browser, err = pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(headless),
		SlowMo:   playwright.Float(slowMo),
	})
	if err != nil {
		_ = pw.Stop()
		_ = serverCmd.Process.Kill()
		log.Fatalf("failed to launch browser: %v", err)
	}

	// run tests
	code := m.Run()

	// cleanup
	_ = browser.Close()
	_ = pw.Stop()
	if serverCmd.Process != nil {
		_ = serverCmd.Process.Kill()
	}
	_ = os.Remove(testDBPath)
	_ = os.RemoveAll(testGitPath)

	os.Exit(code)
}

func waitForServer(serverURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(serverURL) //nolint:gosec // test code with controlled URL
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			return nil
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("server not ready after %v", timeout)
}

// newPage creates a new browser page with isolated context
func newPage(t *testing.T) playwright.Page {
	t.Helper()
	ctx, err := browser.NewContext() // new context per test (isolated cookies/storage)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.Close() })

	page, err := ctx.NewPage()
	require.NoError(t, err)
	return page
}

// waitVisible waits for locator to become visible
func waitVisible(t *testing.T, loc playwright.Locator) {
	t.Helper()
	require.NoError(t, loc.WaitFor(playwright.LocatorWaitForOptions{
		State: playwright.WaitForSelectorStateVisible,
	}))
}

// waitHidden waits for locator to become hidden
func waitHidden(t *testing.T, loc playwright.Locator) {
	t.Helper()
	require.NoError(t, loc.WaitFor(playwright.LocatorWaitForOptions{
		State: playwright.WaitForSelectorStateHidden,
	}))
}

// login performs login (waits for main page to load)
func login(t *testing.T, page playwright.Page, username, password string) { //nolint:unparam // password kept for clarity
	t.Helper()
	_, err := page.Goto(baseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill(username))
	require.NoError(t, page.Locator("#password").Fill(password))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	// wait for main page - check for header which exists for all users
	waitVisible(t, page.Locator(`h1:has-text("Stash")`))
}

// createKey creates a new key via UI
func createKey(t *testing.T, page playwright.Page, key, value string) {
	t.Helper()
	require.NoError(t, page.Locator(`button:has-text("New Key")`).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	require.NoError(t, page.Locator(`input[name="key"]`).Fill(key))
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill(value))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())

	waitHidden(t, modal)
	// wait for table to show the new key
	waitVisible(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, key)))
}

// createKeyWithFormat creates a new key with specified format
func createKeyWithFormat(t *testing.T, page playwright.Page, key, value, format string) {
	t.Helper()
	require.NoError(t, page.Locator(`button:has-text("New Key")`).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	require.NoError(t, page.Locator(`input[name="key"]`).Fill(key))
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill(value))
	_, err := page.Locator(`select[name="format"]`).SelectOption(playwright.SelectOptionValues{Values: &[]string{format}})
	require.NoError(t, err)
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())

	waitHidden(t, modal)
	// wait for table to show the new key
	waitVisible(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, key)))
}

// updateKey updates an existing key value
func updateKey(t *testing.T, page playwright.Page, key, value string) {
	t.Helper()
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, key))
	require.NoError(t, row.Locator(".btn-edit").Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill(value))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)
}

// deleteKey deletes a key via UI
func deleteKey(t *testing.T, page playwright.Page, key string) {
	t.Helper()
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, key))
	require.NoError(t, row.Locator(".btn-danger").Click())
	confirmModal := page.Locator("#confirm-modal")
	waitVisible(t, confirmModal)
	require.NoError(t, page.Locator("#confirm-delete-btn").Click())
	waitHidden(t, confirmModal)
	// wait for row to disappear from table
	waitHidden(t, row)
}

// cleanupKeys removes all keys with given prefix
func cleanupKeys(t *testing.T, page playwright.Page, prefix string) {
	t.Helper()
	for range 10 {
		// count matching rows before deletion
		rows := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, prefix))
		cnt, err := rows.Count()
		require.NoError(t, err)
		if cnt == 0 {
			break
		}

		row := rows.First()
		deleteBtn := row.Locator(".btn-danger")
		vis, err := deleteBtn.IsVisible()
		require.NoError(t, err)
		if !vis {
			break
		}
		require.NoError(t, deleteBtn.Click())
		confirmModal := page.Locator("#confirm-modal")
		waitVisible(t, confirmModal)
		require.NoError(t, page.Locator("#confirm-delete-btn").Click())
		waitHidden(t, confirmModal)

		// wait for row count to decrease
		assert.Eventually(t, func() bool {
			newCnt, e := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, prefix)).Count()
			return e == nil && newCnt < cnt
		}, 5*time.Second, 100*time.Millisecond)
	}
}

// ==================== Auth Tests ====================

func TestAuth_LoginValid(t *testing.T) {
	page := newPage(t)

	_, err := page.Goto(baseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill("admin"))
	require.NoError(t, page.Locator("#password").Fill("testpass"))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	require.NoError(t, page.Locator(`button:has-text("New Key")`).WaitFor())

	assert.Equal(t, baseURL+"/", page.URL())
}

func TestAuth_LoginInvalid(t *testing.T) {
	page := newPage(t)

	_, err := page.Goto(baseURL + "/login")
	require.NoError(t, err)

	require.NoError(t, page.Locator("#username").Fill("admin"))
	require.NoError(t, page.Locator("#password").Fill("wrongpass"))
	require.NoError(t, page.Locator(`button[type="submit"]`).Click())
	// wait for error message to appear
	waitVisible(t, page.Locator(".error-message"))

	assert.Contains(t, page.URL(), "/login")
}

func TestAuth_Logout(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	require.NoError(t, page.Locator(`button[title="Logout"]`).Click())
	require.NoError(t, page.Locator("#username").WaitFor())

	assert.Contains(t, page.URL(), "/login")
}

func TestAuth_ProtectedRouteRedirect(t *testing.T) {
	page := newPage(t)

	// try to access main page without login
	_, err := page.Goto(baseURL + "/")
	require.NoError(t, err)

	// should redirect to login
	assert.Contains(t, page.URL(), "/login")
}

func TestAuth_SessionPersists(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// reload page
	_, err := page.Reload()
	require.NoError(t, err)
	require.NoError(t, page.Locator(`h1:has-text("Stash")`).WaitFor())

	// should still be logged in
	assert.Equal(t, baseURL+"/", page.URL())
}

// ==================== KV CRUD Tests ====================

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

	// click to view
	require.NoError(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)
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
	require.NoError(t, row.Locator(".btn-edit").Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	// update value
	newValue := "updated value"
	require.NoError(t, page.Locator(`textarea[name="value"]`).Fill(newValue))
	require.NoError(t, page.Locator(`#modal-content button[type="submit"]`).Click())
	waitHidden(t, modal)

	// verify by viewing
	require.NoError(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).Click())
	waitVisible(t, modal)
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

// ==================== History Tests (Git Mode) ====================

func TestHistory_ShowsCommits(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	keyName := "e2e-history/commits-test"
	createKey(t, page, keyName, "version 1")
	updateKey(t, page, keyName, "version 2")
	updateKey(t, page, keyName, "version 3")

	// view key
	require.NoError(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

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

	// view key
	require.NoError(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

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

	// view key
	require.NoError(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

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

// ==================== Permissions Tests ====================

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

	visible, _ := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).IsVisible()
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
	visible, _ := keyCell.IsVisible()
	assert.True(t, visible, "readonly user should see the key")

	// but no edit/delete buttons
	editVisible, _ := page.Locator(".btn-edit").First().IsVisible()
	deleteVisible, _ := page.Locator(".btn-danger").First().IsVisible()
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
	insideVisible, _ := insideCell.IsVisible()
	assert.True(t, insideVisible, "scoped user should see app/* key")

	// should not see key outside prefix
	outsideVisible, _ := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, outsideKey)).IsVisible()
	assert.False(t, outsideVisible, "scoped user should not see key outside app/* prefix")

	// cleanup
	deleteKey(t, adminPage, outsideKey)
	deleteKey(t, adminPage, insideKey)
}

// ==================== Search Tests ====================

func TestSearch_FiltersKeyList(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// create test keys
	createKey(t, page, "e2e-search/alpha", "alpha value")
	createKey(t, page, "e2e-search/beta", "beta value")
	createKey(t, page, "e2e-search/gamma", "gamma value")

	// search for alpha - use Eventually for debounced search
	require.NoError(t, page.Locator(`input[name="search"]`).Fill("e2e-search/alpha"))
	assert.Eventually(t, func() bool {
		vis, e := page.Locator(`td.key-cell:has-text("e2e-search/beta")`).IsVisible()
		return e == nil && !vis // beta should be filtered out
	}, 5*time.Second, 100*time.Millisecond, "beta should be filtered out")

	// alpha should be visible
	alphaVisible, _ := page.Locator(`td.key-cell:has-text("e2e-search/alpha")`).IsVisible()
	assert.True(t, alphaVisible, "alpha should be visible")

	// cleanup - clear search and wait for all keys to appear
	require.NoError(t, page.Locator(`input[name="search"]`).Fill(""))
	assert.Eventually(t, func() bool {
		cnt, e := page.Locator(`td.key-cell:has-text("e2e-search")`).Count()
		return e == nil && cnt >= 3
	}, 5*time.Second, 100*time.Millisecond, "all keys should reappear")
	cleanupKeys(t, page, "e2e-search")
}

func TestSearch_ClearShowsAll(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	createKey(t, page, "e2e-search2/one", "one")
	createKey(t, page, "e2e-search2/two", "two")

	// search then clear - use Eventually for debounced search
	require.NoError(t, page.Locator(`input[name="search"]`).Fill("e2e-search2/one"))
	assert.Eventually(t, func() bool {
		vis, e := page.Locator(`td.key-cell:has-text("e2e-search2/two")`).IsVisible()
		return e == nil && !vis // two should be filtered
	}, 5*time.Second, 100*time.Millisecond)

	require.NoError(t, page.Locator(`input[name="search"]`).Fill(""))
	assert.Eventually(t, func() bool {
		cnt, e := page.Locator(`td.key-cell:has-text("e2e-search2")`).Count()
		return e == nil && cnt >= 2
	}, 5*time.Second, 100*time.Millisecond)

	// both should be visible
	oneVisible, _ := page.Locator(`td.key-cell:has-text("e2e-search2/one")`).IsVisible()
	twoVisible, _ := page.Locator(`td.key-cell:has-text("e2e-search2/two")`).IsVisible()
	assert.True(t, oneVisible)
	assert.True(t, twoVisible)

	cleanupKeys(t, page, "e2e-search2")
}

func TestSearch_NoResultsShowsEmpty(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// search for nonexistent - use Eventually for debounced search
	require.NoError(t, page.Locator(`input[name="search"]`).Fill("nonexistent-key-xyz"))
	emptyState := page.Locator(".empty-state")
	assert.Eventually(t, func() bool {
		vis, e := emptyState.IsVisible()
		return e == nil && vis
	}, 5*time.Second, 100*time.Millisecond, "empty state should be shown")
}

// ==================== UI Mode Tests ====================

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
	require.NoError(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)
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
	require.NoError(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).Click())
	waitVisible(t, modal)
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

	// view key
	require.NoError(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, keyName)).Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)
	highlightedCode := page.Locator(".highlighted-code")
	waitVisible(t, highlightedCode)

	// should have highlighted code
	highlighted, _ := highlightedCode.IsVisible()
	assert.True(t, highlighted, "should have syntax highlighting for JSON")

	// cleanup
	require.NoError(t, page.Locator("#main-modal .modal-close").Click())
	waitHidden(t, modal)
	deleteKey(t, page, keyName)
}
