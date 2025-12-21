import { test, expect } from '@playwright/test';

test.describe('authentication', () => {
  test('login with valid credentials redirects to main page', async ({ page }) => {
    await page.goto('/login');
    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpass');
    await page.click('button[type="submit"]');

    await expect(page).toHaveURL('/');
    await expect(page.locator('#keys-table')).toBeVisible();
  });

  test('login with invalid credentials shows error', async ({ page }) => {
    await page.goto('/login');
    await page.fill('#username', 'admin');
    await page.fill('#password', 'wrongpassword');
    await page.click('button[type="submit"]');

    await expect(page).toHaveURL('/login');
    await expect(page.locator('.error-message')).toBeVisible();
  });

  test('logout clears session and redirects to login', async ({ page }) => {
    // first login
    await page.goto('/login');
    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpass');
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL('/');

    // then logout
    await page.click('form[action="/logout"] button');
    await expect(page).toHaveURL('/login');
  });

  test('protected route redirects unauthenticated user to login', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveURL('/login');
  });

  test('session persists across page reload', async ({ page }) => {
    // login
    await page.goto('/login');
    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpass');
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL('/');

    // reload and verify still logged in
    await page.reload();
    await expect(page).toHaveURL('/');
    await expect(page.locator('#keys-table')).toBeVisible();
  });
});
