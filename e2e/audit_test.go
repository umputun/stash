//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAudit_AdminAccess(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// admin should see audit icon in header
	auditLink := page.Locator(`a[href="/audit"]`)
	waitVisible(t, auditLink)

	// click audit link
	require.NoError(t, auditLink.Click())

	// should navigate to audit page
	require.NoError(t, page.WaitForURL(baseURL+"/audit"))

	// page should have audit header
	header := page.Locator(`.audit-header h1:has-text("Audit Log")`)
	waitVisible(t, header)

	// filter panel should be visible
	filterPanel := page.Locator(".filter-panel")
	waitVisible(t, filterPanel)

	// table container should be visible
	tableContainer := page.Locator(".table-container")
	waitVisible(t, tableContainer)
}

func TestAudit_NonAdminNoAccess(t *testing.T) {
	page := newPage(t)
	login(t, page, "readonly", "testpass")

	// non-admin should NOT see audit icon in header
	auditLink := page.Locator(`a[href="/audit"]`)
	visible, err := auditLink.IsVisible()
	require.NoError(t, err)
	assert.False(t, visible, "readonly user should not see audit link")
}

func TestAudit_NonAdminDirectURLAccess(t *testing.T) {
	page := newPage(t)
	login(t, page, "readonly", "testpass")

	// try to navigate directly to audit page
	resp, err := page.Goto(baseURL + "/audit")
	require.NoError(t, err)

	// should return 403 Forbidden
	assert.Equal(t, 403, resp.Status(), "non-admin direct URL access should return 403")

	// verify error message is shown
	errorMsg := page.Locator(`text=Admin access required`)
	waitVisible(t, errorMsg)
}

func TestAudit_LogsActions(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// navigate to audit page
	_, err := page.Goto(baseURL + "/audit")
	require.NoError(t, err)

	// wait for page to load - either table or empty state
	waitVisible(t, page.Locator(`.audit-header h1:has-text("Audit Log")`))

	// verify filter panel exists
	filterPanel := page.Locator(".filter-panel")
	waitVisible(t, filterPanel)

	// verify table container exists (may have .audit-table or .empty-state inside)
	tableContainer := page.Locator(".table-container")
	waitVisible(t, tableContainer)
}

func TestAudit_WebUIActionsLogged(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// create a unique key via web UI
	testKey := "audit-test/webui-key"

	// click new key button
	newBtn := page.Locator(`button:has-text("New Key")`)
	waitVisible(t, newBtn)
	require.NoError(t, newBtn.Click())

	// fill in the form
	keyInput := page.Locator(`#modal-content input[name="key"]`)
	waitVisible(t, keyInput)
	require.NoError(t, keyInput.Fill(testKey))

	valueInput := page.Locator(`#modal-content textarea[name="value"]`)
	require.NoError(t, valueInput.Fill("test value for audit"))

	// submit the form
	submitBtn := page.Locator(`#modal-content button[type="submit"]`)
	require.NoError(t, submitBtn.Click())

	// wait for modal to close and keys list to refresh
	waitHidden(t, page.Locator("#main-modal.active"))

	// navigate to audit page
	auditLink := page.Locator(`a[href="/audit"]`)
	waitVisible(t, auditLink)
	require.NoError(t, auditLink.Click())
	require.NoError(t, page.WaitForURL(baseURL+"/audit"))

	// wait for audit table to load
	waitVisible(t, page.Locator(`.audit-header h1:has-text("Audit Log")`))

	// verify the create action appears in the audit log
	auditTable := page.Locator(".audit-table")
	waitVisible(t, auditTable)

	// find the row with our key
	keyCell := page.Locator(`.audit-table .col-key:has-text("` + testKey + `")`)
	waitVisible(t, keyCell)

	// verify the action is CREATE
	row := keyCell.Locator("xpath=..")
	actionBadge := row.Locator(".col-action .badge")
	actionText, err := actionBadge.TextContent()
	require.NoError(t, err)
	assert.Equal(t, "CREATE", actionText)

	// verify the actor is admin
	actorCell := row.Locator(".col-actor")
	actorText, err := actorCell.TextContent()
	require.NoError(t, err)
	assert.Equal(t, "admin", actorText)

	// verify the result is success
	resultBadge := row.Locator(".col-result .badge")
	resultText, err := resultBadge.TextContent()
	require.NoError(t, err)
	assert.Equal(t, "success", resultText)
}

func TestAudit_FilterFormWorks(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// navigate to audit page
	_, err := page.Goto(baseURL + "/audit")
	require.NoError(t, err)

	// wait for filter panel
	filterPanel := page.Locator(".filter-panel")
	waitVisible(t, filterPanel)

	// verify filter form fields exist
	keyInput := page.Locator(`input[name="key"]`)
	waitVisible(t, keyInput)

	actorInput := page.Locator(`input[name="actor"]`)
	waitVisible(t, actorInput)

	actionSelect := page.Locator(`select[name="action"]`)
	waitVisible(t, actionSelect)

	resultSelect := page.Locator(`select[name="result"]`)
	waitVisible(t, resultSelect)

	// fill in a filter value
	require.NoError(t, keyInput.Fill("test/*"))

	// click apply button and verify no errors
	applyBtn := page.Locator(`.filter-actions button[type="submit"]`)
	require.NoError(t, applyBtn.Click())

	// wait for table container refresh (will show empty state or table)
	waitVisible(t, page.Locator(".table-container"))
}

func TestAudit_BackToMain(t *testing.T) {
	page := newPage(t)
	login(t, page, "admin", "testpass")

	// navigate to audit page
	_, err := page.Goto(baseURL + "/audit")
	require.NoError(t, err)
	waitVisible(t, page.Locator(`.audit-header h1:has-text("Audit Log")`))

	// click back link
	backLink := page.Locator(`a[href="/"]`)
	require.NoError(t, backLink.Click())

	// should be back on main page
	require.NoError(t, page.WaitForURL(baseURL+"/"))
	waitVisible(t, page.Locator(`h1:has-text("Stash")`))
}

func TestAudit_Pagination(t *testing.T) {
	const apiToken = "e2e-admin-token-12345"

	page := newPage(t)
	login(t, page, "admin", "testpass")

	// create 105 keys via API to generate audit entries (page size is 100)
	for i := range 105 {
		key := fmt.Sprintf("pagination-test/key%03d", i)
		req, err := http.NewRequest(http.MethodPut, baseURL+"/kv/"+key, strings.NewReader("value"))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+apiToken)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
	}

	// navigate to audit page
	_, err := page.Goto(baseURL + "/audit")
	require.NoError(t, err)
	waitVisible(t, page.Locator(`.audit-header h1:has-text("Audit Log")`))

	// wait for table to load
	auditTable := page.Locator(".audit-table")
	waitVisible(t, auditTable)

	// verify pagination shows page 1 (use .stats to target visible pagination, not hidden OOB)
	pageInfo := page.Locator(".stats #pagination .page-info")
	waitVisible(t, pageInfo)
	pageText, err := pageInfo.TextContent()
	require.NoError(t, err)
	assert.Contains(t, pageText, "1 /")

	// capture first key on page 1 to verify page 2 shows different content
	firstRowPage1 := page.Locator(".audit-table tbody tr").First().Locator(".col-key")
	page1FirstKey, err := firstRowPage1.TextContent()
	require.NoError(t, err)
	require.NotEmpty(t, page1FirstKey, "page 1 should have entries")

	// click next page button and wait for HTMX response
	nextBtn := page.Locator(".stats #pagination .btn-page:not(.disabled)").Last()
	waitVisible(t, nextBtn)
	htmxResp, err := page.ExpectResponse(regexp.MustCompile(`/web/audit`), func() error {
		return nextBtn.Click()
	}, playwright.PageExpectResponseOptions{Timeout: playwright.Float(15000)})
	require.NoError(t, err)
	require.Equal(t, 200, htmxResp.Status())

	// verify we're on page 2
	waitVisible(t, auditTable)
	pageText, err = pageInfo.TextContent()
	require.NoError(t, err)
	assert.Contains(t, pageText, "2 /")

	// verify page 2 shows different entries than page 1
	firstRowPage2 := page.Locator(".audit-table tbody tr").First().Locator(".col-key")
	page2FirstKey, err := firstRowPage2.TextContent()
	require.NoError(t, err)
	require.NotEmpty(t, page2FirstKey, "page 2 should have entries")
	assert.NotEqual(t, page1FirstKey, page2FirstKey, "page 2 should show different entries than page 1")

	// click previous page button and wait for HTMX response
	prevBtn := page.Locator(".stats #pagination .btn-page:not(.disabled)").First()
	htmxResp, err = page.ExpectResponse(regexp.MustCompile(`/web/audit`), func() error {
		return prevBtn.Click()
	}, playwright.PageExpectResponseOptions{Timeout: playwright.Float(15000)})
	require.NoError(t, err)
	require.Equal(t, 200, htmxResp.Status())

	// verify we're back on page 1 with original content
	waitVisible(t, auditTable)
	pageText, err = pageInfo.TextContent()
	require.NoError(t, err)
	assert.Contains(t, pageText, "1 /")

	// verify page 1 shows same first entry as before
	firstRowBack := page.Locator(".audit-table tbody tr").First().Locator(".col-key")
	page1KeyBack, err := firstRowBack.TextContent()
	require.NoError(t, err)
	assert.Equal(t, page1FirstKey, page1KeyBack, "returning to page 1 should show same entries")
}
