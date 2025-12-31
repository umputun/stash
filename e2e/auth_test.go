//go:build e2e

package e2e

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
