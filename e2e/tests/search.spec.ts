import { test, expect } from '@playwright/test';

test.describe('search functionality', () => {
  test.use({ storageState: '.auth/admin.json' });

  const testKeyPrefix = 'e2e-search-test';

  // helper to force close any open modal via JavaScript
  async function forceCloseModals(page: import('@playwright/test').Page) {
    await page.evaluate(() => {
      document.querySelectorAll('.modal-backdrop').forEach((modal) => {
        modal.classList.remove('active');
      });
    });
    await page.waitForTimeout(100);
  }

  // helper to create a key with proper form wait
  async function createKey(page: import('@playwright/test').Page, key: string, value: string) {
    await forceCloseModals(page);
    await page.click('button:has-text("New Key")');
    await expect(page.locator('#main-modal.active')).toBeVisible();
    const keyInput = page.locator('input[name="key"]');
    const valueInput = page.locator('textarea[name="value"]');
    await expect(keyInput).toBeVisible();
    await expect(valueInput).toBeVisible();
    await keyInput.fill(key);
    await valueInput.fill(value);
    await page.click('#modal-content button[type="submit"]');
    await expect(page.locator('#main-modal.active')).not.toBeVisible({ timeout: 5000 });
    await page.waitForLoadState('networkidle');
  }

  test.beforeAll(async ({ browser }) => {
    // create test keys
    const context = await browser.newContext({ storageState: '.auth/admin.json' });
    const page = await context.newPage();
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const keys = ['alpha', 'beta', 'gamma'];
    for (const key of keys) {
      const keyName = `${testKeyPrefix}/${key}`;
      const exists = await page.locator(`td.key-cell:has-text("${keyName}")`).isVisible();
      if (!exists) {
        await createKey(page, keyName, `value for ${key}`);
        await forceCloseModals(page);
        await page.waitForTimeout(200);
      }
    }
    await context.close();
  });

  test.afterAll(async ({ browser }) => {
    // cleanup test keys
    const context = await browser.newContext({ storageState: '.auth/admin.json' });
    const page = await context.newPage();
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // limited cleanup loop to avoid timeout
    for (let i = 0; i < 10; i++) {
      await forceCloseModals(page);
      const row = page.locator(`tr:has-text("${testKeyPrefix}")`).first();
      if (!(await row.isVisible())) break;
      const deleteBtn = row.locator('.btn-danger');
      if (await deleteBtn.isVisible()) {
        await deleteBtn.click();
        await page.locator('#confirm-delete-btn').click();
        await page.waitForTimeout(200);
      } else {
        break;
      }
    }
    await context.close();
  });

  test('search filters key list', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // type in search and wait for HTMX to update table
    await page.fill('input[name="search"]', `${testKeyPrefix}/alpha`);
    await expect(page.locator(`td.key-cell:has-text("${testKeyPrefix}/beta")`)).not.toBeVisible({ timeout: 5000 });

    // should only show matching key
    await expect(page.locator(`td.key-cell:has-text("${testKeyPrefix}/alpha")`)).toBeVisible();
    await expect(page.locator(`td.key-cell:has-text("${testKeyPrefix}/gamma")`)).not.toBeVisible();
  });

  test('clear search shows all keys', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // search first
    await page.fill('input[name="search"]', `${testKeyPrefix}/alpha`);
    await expect(page.locator(`td.key-cell:has-text("${testKeyPrefix}/beta")`)).not.toBeVisible({ timeout: 5000 });

    // clear search and wait for all keys to reappear
    await page.fill('input[name="search"]', '');
    await expect(page.locator(`td.key-cell:has-text("${testKeyPrefix}/beta")`)).toBeVisible({ timeout: 5000 });

    // all test keys should be visible
    await expect(page.locator(`td.key-cell:has-text("${testKeyPrefix}/alpha")`)).toBeVisible();
    await expect(page.locator(`td.key-cell:has-text("${testKeyPrefix}/gamma")`)).toBeVisible();
  });

  test('search with no results shows empty state', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // search for non-existent key and wait for empty state
    await page.fill('input[name="search"]', 'nonexistent-key-xyz-123');
    await expect(page.locator('#key-count').first()).toContainText('no keys matching', { timeout: 5000 });
  });
});
