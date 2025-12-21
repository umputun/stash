import { test, expect } from '@playwright/test';

test.describe('kv history (git mode)', () => {
  test.use({ storageState: '.auth/admin.json' });

  const testKeyPrefix = 'e2e-history-test';

  // helper to create a key with proper form wait
  async function createKey(page: import('@playwright/test').Page, key: string, value: string) {
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
    await expect(page.locator(`td.key-cell:has-text("${key}")`)).toBeVisible();
    await page.waitForLoadState('networkidle');
    // small delay to let HTMX process new elements
    await page.waitForTimeout(100);
  }

  // helper to update a key value
  async function updateKey(page: import('@playwright/test').Page, key: string, value: string) {
    // ensure page is stable before interacting
    await page.waitForLoadState('networkidle');
    // small delay to let HTMX process new elements after table swap
    await page.waitForTimeout(100);
    // wait for the row to be stable before clicking edit
    const row = page.locator(`tr:has-text("${key}")`);
    await expect(row).toBeVisible();
    const editBtn = row.locator('.btn-edit');
    await expect(editBtn).toBeVisible();
    await editBtn.click();
    await expect(page.locator('#main-modal.active')).toBeVisible({ timeout: 5000 });
    const valueInput = page.locator('textarea[name="value"]');
    await expect(valueInput).toBeVisible();
    await valueInput.fill(value);
    await page.click('#modal-content button[type="submit"]');
    await expect(page.locator('#main-modal.active')).not.toBeVisible({ timeout: 5000 });
    await page.waitForLoadState('networkidle');
  }

  // helper to force close any open modal via JavaScript
  async function forceCloseModals(page: import('@playwright/test').Page) {
    await page.evaluate(() => {
      document.querySelectorAll('.modal-backdrop').forEach((modal) => {
        modal.classList.remove('active');
      });
    });
    await page.waitForTimeout(100);
  }

  // cleanup before each test
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // quick cleanup of any leftover test keys
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
  });

  test('history shows commits for a key', async ({ page }) => {
    const keyName = `${testKeyPrefix}/history-key`;
    await createKey(page, keyName, 'version 1');
    await updateKey(page, keyName, 'version 2');
    await updateKey(page, keyName, 'version 3');

    // view key to see history button - wait for cell to be stable first
    await page.waitForLoadState('networkidle');
    const keyCell = page.locator(`tr:has-text("${keyName}") td.key-cell`);
    await expect(keyCell).toBeVisible();
    await keyCell.click();
    await expect(page.locator('#main-modal.active')).toBeVisible();

    // find and click history button
    const historyBtn = page.locator('button:has-text("History")');
    await expect(historyBtn).toBeVisible();
    await historyBtn.click();
    // wait for HTMX to load history content
    await page.waitForLoadState('networkidle');

    // should see history table
    await expect(page.locator('.history-table')).toBeVisible();
  });

  test('view specific revision shows old value', async ({ page }) => {
    const keyName = `${testKeyPrefix}/revision-key`;
    const initialValue = 'initial value';
    const updatedValue = 'updated value';
    await createKey(page, keyName, initialValue);
    await updateKey(page, keyName, updatedValue);

    // view key - wait for cell to be stable first
    await page.waitForLoadState('networkidle');
    const keyCell = page.locator(`tr:has-text("${keyName}") td.key-cell`);
    await expect(keyCell).toBeVisible();
    await keyCell.click();
    await expect(page.locator('#main-modal.active')).toBeVisible();

    // click history button
    const historyBtn = page.locator('button:has-text("History")');
    await expect(historyBtn).toBeVisible();
    await historyBtn.click();
    await page.waitForLoadState('networkidle');

    // history table should be visible with revisions
    await expect(page.locator('.history-table')).toBeVisible();

    // click on oldest revision row (last in list) to view it - rows are clickable
    const historyRows = page.locator('.history-table tbody tr');
    const oldestRow = historyRows.last();
    await expect(oldestRow).toBeVisible();
    // click on a non-action cell in the row to trigger view
    await oldestRow.locator('td').first().click();
    await page.waitForLoadState('networkidle');

    // verify the old value is displayed in revision view
    await expect(page.locator('.value-content')).toContainText(initialValue);
  });

  test('restore from revision updates current value', async ({ page }) => {
    const keyName = `${testKeyPrefix}/restore-key`;
    const originalValue = 'original value to restore';
    const newValue = 'new value after change';
    await createKey(page, keyName, originalValue);
    await updateKey(page, keyName, newValue);

    // view key - wait for cell to be stable first
    await page.waitForLoadState('networkidle');
    const keyCell1 = page.locator(`tr:has-text("${keyName}") td.key-cell`);
    await expect(keyCell1).toBeVisible();
    await keyCell1.click();
    await expect(page.locator('#main-modal.active')).toBeVisible();

    // click history button
    const historyBtn = page.locator('button:has-text("History")');
    await expect(historyBtn).toBeVisible();
    await historyBtn.click();
    await page.waitForLoadState('networkidle');

    // find restore button for original revision (oldest commit is last in list)
    const restoreBtn = page.locator('button:has-text("Restore")').last();
    await expect(restoreBtn).toBeVisible();
    await restoreBtn.click();
    await page.waitForLoadState('networkidle');

    // modal closes after restore, wait for it
    await forceCloseModals(page);

    // reload and view key to verify restored value
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const keyCell2 = page.locator(`tr:has-text("${keyName}") td.key-cell`);
    await expect(keyCell2).toBeVisible();
    await keyCell2.click();
    await expect(page.locator('#main-modal.active')).toBeVisible();

    // check value was restored
    await expect(page.locator('.value-content').last()).toContainText(originalValue);
  });
});
