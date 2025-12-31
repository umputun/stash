//go:build e2e

package e2e

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	alphaVisible, err := page.Locator(`td.key-cell:has-text("e2e-search/alpha")`).IsVisible()
	require.NoError(t, err)
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
	oneVisible, err := page.Locator(`td.key-cell:has-text("e2e-search2/one")`).IsVisible()
	require.NoError(t, err)
	twoVisible, err := page.Locator(`td.key-cell:has-text("e2e-search2/two")`).IsVisible()
	require.NoError(t, err)
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
