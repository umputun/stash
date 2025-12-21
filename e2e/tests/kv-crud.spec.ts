import { test, expect } from '@playwright/test';

test.describe('kv crud operations', () => {
  test.use({ storageState: '.auth/admin.json' });

  const testKeyPrefix = 'e2e-crud-test';

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
    // wait for HTMX to finish processing the new table content
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

  // cleanup before each test (ensures clean state)
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

  test('creates new key via form', async ({ page }) => {
    const keyName = `${testKeyPrefix}/new-key`;
    const keyValue = 'test value content';
    await createKey(page, keyName, keyValue);
  });

  test('views key in modal', async ({ page }) => {
    const keyName = `${testKeyPrefix}/view-test`;
    const keyValue = 'value to view';
    await createKey(page, keyName, keyValue);

    // click row to view - wait for cell to be stable first
    const keyCell = page.locator(`tr:has-text("${keyName}") td.key-cell`);
    await expect(keyCell).toBeVisible();
    await keyCell.click();
    await expect(page.locator('#main-modal.active')).toBeVisible();
    await expect(page.locator('.value-display').last()).toContainText(keyValue);
  });

  test('edits existing key', async ({ page }) => {
    const keyName = `${testKeyPrefix}/edit-test`;
    const originalValue = 'original value';
    const updatedValue = 'updated value';
    await createKey(page, keyName, originalValue);

    // click edit button - wait for row to be stable first
    const row = page.locator(`tr:has-text("${keyName}")`);
    await expect(row).toBeVisible();
    const editBtn = row.locator('.btn-edit');
    await expect(editBtn).toBeVisible();
    await editBtn.click();
    await expect(page.locator('#main-modal.active')).toBeVisible();
    const valueInput = page.locator('textarea[name="value"]');
    await expect(valueInput).toBeVisible();
    await valueInput.fill(updatedValue);
    await page.click('#modal-content button[type="submit"]');
    await expect(page.locator('#main-modal.active')).not.toBeVisible({ timeout: 5000 });

    // verify updated value - wait for cell to be stable first
    const viewCell = page.locator(`tr:has-text("${keyName}") td.key-cell`);
    await expect(viewCell).toBeVisible();
    await viewCell.click();
    await expect(page.locator('#main-modal.active')).toBeVisible();
    await expect(page.locator('.value-display').last()).toContainText(updatedValue);
  });

  test('deletes key with confirmation', async ({ page }) => {
    const keyName = `${testKeyPrefix}/delete-test`;
    await createKey(page, keyName, 'to be deleted');

    // click delete
    const deleteRow = page.locator(`tr:has-text("${keyName}")`);
    await expect(deleteRow).toBeVisible();
    const deleteBtn = deleteRow.locator('.btn-danger');
    await expect(deleteBtn).toBeVisible();
    await deleteBtn.click();
    await expect(page.locator('#confirm-modal')).toBeVisible();
    await expect(page.locator('#confirm-key')).toContainText(keyName);

    // confirm delete
    await page.click('#confirm-delete-btn');

    // verify key is gone
    await expect(page.locator(`td.key-cell:has-text("${keyName}")`)).not.toBeVisible();
  });

  test('creates key with slashes in path', async ({ page }) => {
    const keyName = `${testKeyPrefix}/nested/deep/key`;
    const keyValue = 'nested value';
    await createKey(page, keyName, keyValue);
  });
});
