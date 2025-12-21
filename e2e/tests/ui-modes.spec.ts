import { test, expect } from '@playwright/test';

test.describe('ui modes', () => {
  test.use({ storageState: '.auth/admin.json' });

  const testKeyPrefix = 'e2e-ui-test';

  // helper to force close any open modal via JavaScript
  async function forceCloseModals(page: import('@playwright/test').Page) {
    await page.evaluate(() => {
      document.querySelectorAll('.modal-backdrop').forEach((modal) => {
        modal.classList.remove('active');
      });
    });
    await page.waitForTimeout(100);
  }

  test.beforeEach(async ({ page }) => {
    // create a test key for ui tests
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const exists = await page.locator(`td.key-cell:has-text("${testKeyPrefix}")`).isVisible();
    if (!exists) {
      await page.click('button:has-text("New Key")');
      await expect(page.locator('#main-modal.active')).toBeVisible();
      const keyInput = page.locator('input[name="key"]');
      const valueInput = page.locator('textarea[name="value"]');
      await expect(keyInput).toBeVisible();
      await expect(valueInput).toBeVisible();
      await keyInput.fill(`${testKeyPrefix}/sample`);
      await valueInput.fill('{"key": "value"}');
      await page.selectOption('select[name="format"]', 'json');
      await page.click('#modal-content button[type="submit"]');
      await expect(page.locator('#main-modal.active')).not.toBeVisible({ timeout: 5000 });
      await expect(page.locator(`td.key-cell:has-text("${testKeyPrefix}")`)).toBeVisible();
      await page.waitForLoadState('networkidle');
    }
  });

  test.afterAll(async ({ browser }) => {
    // cleanup
    const context = await browser.newContext({ storageState: '.auth/admin.json' });
    const page = await context.newPage();
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await forceCloseModals(page);

    const row = page.locator(`tr:has-text("${testKeyPrefix}")`).first();
    if (await row.isVisible()) {
      await row.locator('.btn-danger').click();
      await page.locator('#confirm-delete-btn').click();
      await page.waitForTimeout(300);
    }
    await context.close();
  });

  test('theme toggle switches between light and dark', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // get initial theme
    const initialTheme = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));

    // click theme toggle and wait for attribute change
    await page.click('form[hx-post="/web/theme"] button');
    await expect(page.locator('html')).not.toHaveAttribute('data-theme', initialTheme || '', { timeout: 5000 });

    // verify theme changed
    const newTheme = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
    expect(newTheme).not.toBe(initialTheme);
  });

  test('view mode toggles between table and cards', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // should start in table view (no cards container)
    await expect(page.locator('table')).toBeVisible();

    // click view mode toggle and wait for cards to appear
    await page.click('button[hx-post="/web/view-mode"]');
    await expect(page.locator('.cards-container')).toBeVisible({ timeout: 5000 });

    // toggle back and wait for table to reappear
    await page.click('button[hx-post="/web/view-mode"]');
    await expect(page.locator('table')).toBeVisible({ timeout: 5000 });
  });

  test('sort button cycles through modes', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // click sort button multiple times to verify it cycles
    const sortButton = page.locator('.sort-button');
    await expect(sortButton).toBeVisible();

    // click and wait for networkidle (HTMX request completes)
    await sortButton.click();
    await page.waitForLoadState('networkidle');
    await expect(sortButton).toBeVisible();

    await sortButton.click();
    await page.waitForLoadState('networkidle');
    await expect(sortButton).toBeVisible();
  });

  test('format selector shows all options', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.click('button:has-text("New Key")');

    const formatSelect = page.locator('select[name="format"]');
    await expect(formatSelect).toBeVisible();

    // verify all format options exist
    const options = await formatSelect.locator('option').allTextContents();
    expect(options).toContain('text');
    expect(options).toContain('json');
    expect(options).toContain('yaml');
    expect(options).toContain('xml');

    // close modal via js
    await forceCloseModals(page);
  });

  test('syntax highlighting applied for json content', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // wait for the test key to be visible
    const keyCell = page.locator(`tr:has-text("${testKeyPrefix}") td.key-cell`);
    await expect(keyCell).toBeVisible({ timeout: 5000 });

    // click on the json key to view
    await keyCell.click();
    await expect(page.locator('#main-modal.active')).toBeVisible();

    // verify highlighted code is present
    await expect(page.locator('.highlighted-code')).toBeVisible();
  });
});
