//go:build e2e

// Package e2e contains end-to-end tests for the Stash web UI.
//
// Test organization:
//   - e2e_test.go: TestMain, shared helpers, constants
//   - auth_test.go: authentication tests (login, logout, sessions)
//   - kv_test.go: KV CRUD tests (create, view, edit, delete)
//   - history_test.go: git history tests (commits, revisions, restore)
//   - permissions_test.go: permission tests (admin, readonly, scoped)
//   - search_test.go: search functionality tests
//   - ui_test.go: UI mode tests (theme, view mode, sort, format)
//   - zk_test.go: zero-knowledge encryption tests
//   - secrets_test.go: server-side secrets tests (separate server)
package e2e

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
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
		"--audit.enabled",
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

// waitVisible waits for locator to become visible.
// timeout is 15s to accommodate CI environments with variable performance.
func waitVisible(t *testing.T, loc playwright.Locator) {
	t.Helper()
	require.NoError(t, loc.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(15000),
	}))
}

// waitHidden waits for locator to become hidden.
// timeout is 15s to accommodate CI environments with variable performance.
func waitHidden(t *testing.T, loc playwright.Locator) {
	t.Helper()
	require.NoError(t, loc.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateHidden,
		Timeout: playwright.Float(15000),
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
	newKeyBtn := page.Locator(`button:has-text("New Key")`)
	waitVisible(t, newKeyBtn)
	require.NoError(t, newKeyBtn.Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	// wait for form inputs to be visible and interactive
	keyInput := page.Locator(`input[name="key"]`)
	waitVisible(t, keyInput)
	require.NoError(t, keyInput.Fill(key))
	valueInput := page.Locator(`textarea[name="value"]`)
	waitVisible(t, valueInput)
	require.NoError(t, valueInput.Fill(value))
	submitBtn := page.Locator(`#modal-content button[type="submit"]`)
	waitVisible(t, submitBtn)

	// click submit and wait for HTMX response to complete
	resp, err := page.ExpectResponse(baseURL+"/web/keys", func() error {
		return submitBtn.Click()
	}, playwright.PageExpectResponseOptions{Timeout: playwright.Float(15000)})
	require.NoError(t, err)
	require.Equal(t, 200, resp.Status())

	// now wait for the key to appear in table (DOM updated after response)
	waitVisible(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, key)))
}

// createKeyWithFormat creates a new key with specified format
func createKeyWithFormat(t *testing.T, page playwright.Page, key, value, format string) {
	t.Helper()
	newKeyBtn := page.Locator(`button:has-text("New Key")`)
	waitVisible(t, newKeyBtn)
	require.NoError(t, newKeyBtn.Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	// wait for form inputs to be visible and interactive
	keyInput := page.Locator(`input[name="key"]`)
	waitVisible(t, keyInput)
	require.NoError(t, keyInput.Fill(key))
	valueInput := page.Locator(`textarea[name="value"]`)
	waitVisible(t, valueInput)
	require.NoError(t, valueInput.Fill(value))
	formatSelect := page.Locator(`select[name="format"]`)
	waitVisible(t, formatSelect)
	_, err := formatSelect.SelectOption(playwright.SelectOptionValues{Values: &[]string{format}})
	require.NoError(t, err)
	submitBtn := page.Locator(`#modal-content button[type="submit"]`)
	waitVisible(t, submitBtn)

	// click submit and wait for HTMX response to complete
	resp, err := page.ExpectResponse(baseURL+"/web/keys", func() error {
		return submitBtn.Click()
	}, playwright.PageExpectResponseOptions{Timeout: playwright.Float(15000)})
	require.NoError(t, err)
	require.Equal(t, 200, resp.Status())

	// now wait for the key to appear in table (DOM updated after response)
	waitVisible(t, page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, key)))
}

// updateKey updates an existing key value
func updateKey(t *testing.T, page playwright.Page, key, value string) {
	t.Helper()
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, key))
	editBtn := row.Locator(".btn-edit")
	waitVisible(t, editBtn) // ensure button is ready after HTMX swap
	require.NoError(t, editBtn.Click())
	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)

	textarea := page.Locator(`textarea[name="value"]`)
	waitVisible(t, textarea)
	require.NoError(t, textarea.Fill(value))
	submitBtn := page.Locator(`#modal-content button[type="submit"]`)
	waitVisible(t, submitBtn)

	// click submit and wait for HTMX response to complete
	resp, err := page.ExpectResponse(regexp.MustCompile(`/web/keys/`), func() error {
		return submitBtn.Click()
	}, playwright.PageExpectResponseOptions{Timeout: playwright.Float(15000)})
	require.NoError(t, err)
	require.Equal(t, 200, resp.Status())

	// wait for table refresh (edit button reappears after HTMX swap completes)
	waitVisible(t, row.Locator(".btn-edit"))
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

// viewKey opens the view modal for a key and returns the modal locator
func viewKey(t *testing.T, page playwright.Page, key string) playwright.Locator {
	t.Helper()
	keyCell := page.Locator(fmt.Sprintf(`td.key-cell:has-text(%q)`, key))
	waitVisible(t, keyCell) // ensure element ready after HTMX swap

	// click and wait for HTMX response to complete
	_, err := page.ExpectResponse(regexp.MustCompile(`/web/keys/view/`), func() error {
		return keyCell.Click()
	}, playwright.PageExpectResponseOptions{Timeout: playwright.Float(15000)})
	require.NoError(t, err)

	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)
	return modal
}

// viewKeyByText opens the view modal for a key using row text matching.
// use this for keys with icons (ZK, secrets) where td.key-cell:has-text() may fail
// due to trailing whitespace from icon SVG elements. tr:has-text() does partial matching
// on the entire row, avoiding the whitespace issue.
func viewKeyByText(t *testing.T, page playwright.Page, key string) playwright.Locator {
	t.Helper()
	// find row by text content (tr:has-text does partial match, works with icon whitespace)
	row := page.Locator(fmt.Sprintf(`tr:has-text(%q)`, key))
	waitVisible(t, row)
	// click the key cell within the row - use First() to be explicit
	keyCell := row.Locator("td.key-cell").First()
	waitVisible(t, keyCell) // ensure cell is ready before click

	// click and wait for HTMX response to complete
	_, err := page.ExpectResponse(regexp.MustCompile(`/web/keys/view/`), func() error {
		return keyCell.Click()
	}, playwright.PageExpectResponseOptions{Timeout: playwright.Float(15000)})
	require.NoError(t, err)

	modal := page.Locator("#main-modal.active")
	waitVisible(t, modal)
	return modal
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
