import { test, expect } from '@playwright/test';

test.describe('permissions', () => {
  const testKeyPrefix = 'e2e-perm-test';
  const appKeyPrefix = 'app/e2e-perm-test';

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
  }

  // helper to cleanup keys with a prefix
  async function cleanupKeys(page: import('@playwright/test').Page, prefix: string) {
    for (let i = 0; i < 10; i++) {
      await forceCloseModals(page);
      const row = page.locator(`tr:has-text("${prefix}")`).first();
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
  }

  test.describe('admin user', () => {
    test.use({ storageState: '.auth/admin.json' });

    test.beforeEach(async ({ page }) => {
      await page.goto('/');
      await page.waitForLoadState('networkidle');
      await cleanupKeys(page, testKeyPrefix);
      await cleanupKeys(page, appKeyPrefix);
    });

    test('admin can create, edit, and delete any key', async ({ page }) => {
      const keyName = `${testKeyPrefix}/admin-key`;

      // create
      await createKey(page, keyName, 'admin value');

      // edit - wait for row to be stable first
      const row = page.locator(`tr:has-text("${keyName}")`);
      await expect(row).toBeVisible();
      const editBtn = row.locator('.btn-edit');
      await expect(editBtn).toBeVisible();
      await editBtn.click();
      await expect(page.locator('#main-modal.active')).toBeVisible();
      const valueInput = page.locator('textarea[name="value"]');
      await expect(valueInput).toBeVisible();
      await valueInput.fill('updated by admin');
      await page.click('#modal-content button[type="submit"]');
      await expect(page.locator('#main-modal.active')).not.toBeVisible({ timeout: 5000 });

      // delete - wait for row to be stable first
      const deleteRow = page.locator(`tr:has-text("${keyName}")`);
      await expect(deleteRow).toBeVisible();
      const deleteBtn = deleteRow.locator('.btn-danger');
      await expect(deleteBtn).toBeVisible();
      await deleteBtn.click();
      await page.click('#confirm-delete-btn');
      await expect(page.locator(`td.key-cell:has-text("${keyName}")`)).not.toBeVisible();
    });
  });

  test.describe('readonly user', () => {
    test.use({ storageState: '.auth/readonly.json' });

    test('readonly user cannot see create button', async ({ page }) => {
      await page.goto('/');
      await page.waitForLoadState('networkidle');
      await expect(page.locator('button:has-text("New Key")')).not.toBeVisible();
    });

    test('readonly user cannot see edit and delete buttons', async ({ page }) => {
      // first create a key as admin so we have something to check
      const adminContext = await page.context().browser()!.newContext({ storageState: '.auth/admin.json' });
      const adminPage = await adminContext.newPage();
      await adminPage.goto('/');
      await adminPage.waitForLoadState('networkidle');

      const testKey = `${testKeyPrefix}/readonly-check`;
      const exists = await adminPage.locator(`td.key-cell:has-text("${testKey}")`).isVisible();
      if (!exists) {
        await adminPage.click('button:has-text("New Key")');
        await adminPage.locator('input[name="key"]').fill(testKey);
        await adminPage.locator('textarea[name="value"]').fill('test');
        await adminPage.click('#modal-content button[type="submit"]');
        await adminPage.waitForLoadState('networkidle');
      }
      await adminContext.close();

      // now check as readonly user - key should be visible but no action buttons
      await page.goto('/');
      await page.waitForLoadState('networkidle');
      await expect(page.locator(`td.key-cell:has-text("${testKey}")`)).toBeVisible();
      await expect(page.locator('.btn-edit')).not.toBeVisible();
      await expect(page.locator('.btn-danger')).not.toBeVisible();

      // cleanup as admin
      const cleanupContext = await page.context().browser()!.newContext({ storageState: '.auth/admin.json' });
      const cleanupPage = await cleanupContext.newPage();
      await cleanupPage.goto('/');
      await cleanupPage.waitForLoadState('networkidle');
      await cleanupKeys(cleanupPage, testKeyPrefix);
      await cleanupContext.close();
    });
  });

  test.describe('scoped user', () => {
    test.use({ storageState: '.auth/scoped.json' });

    test('scoped user only sees keys in allowed prefix', async ({ page }) => {
      // first create keys as admin
      const adminContext = await page.context().browser()!.newContext({ storageState: '.auth/admin.json' });
      const adminPage = await adminContext.newPage();

      await adminPage.goto('/');
      await adminPage.waitForLoadState('networkidle');

      // cleanup any existing test keys first
      await cleanupKeys(adminPage, testKeyPrefix);
      await cleanupKeys(adminPage, appKeyPrefix);

      // create key outside app/ prefix
      await adminPage.click('button:has-text("New Key")');
      await expect(adminPage.locator('#main-modal.active')).toBeVisible();
      const keyInput1 = adminPage.locator('input[name="key"]');
      const valueInput1 = adminPage.locator('textarea[name="value"]');
      await expect(keyInput1).toBeVisible();
      await expect(valueInput1).toBeVisible();
      await keyInput1.fill(`${testKeyPrefix}/outside`);
      await valueInput1.fill('outside scope');
      await adminPage.click('#modal-content button[type="submit"]');
      await expect(adminPage.locator('#main-modal.active')).not.toBeVisible({ timeout: 5000 });

      // create key inside app/ prefix
      await adminPage.click('button:has-text("New Key")');
      await expect(adminPage.locator('#main-modal.active')).toBeVisible();
      const keyInput2 = adminPage.locator('input[name="key"]');
      const valueInput2 = adminPage.locator('textarea[name="value"]');
      await expect(keyInput2).toBeVisible();
      await expect(valueInput2).toBeVisible();
      await keyInput2.fill(appKeyPrefix);
      await valueInput2.fill('inside scope');
      await adminPage.click('#modal-content button[type="submit"]');
      await expect(adminPage.locator('#main-modal.active')).not.toBeVisible({ timeout: 5000 });

      await adminContext.close();

      // now check as scoped user
      await page.goto('/');
      await page.waitForLoadState('networkidle');

      // should see app/* key
      await expect(page.locator(`td.key-cell:has-text("${appKeyPrefix}")`)).toBeVisible();

      // should not see key outside app/ prefix
      await expect(page.locator(`td.key-cell:has-text("${testKeyPrefix}/outside")`)).not.toBeVisible();

      // cleanup as admin
      const cleanupContext = await page.context().browser()!.newContext({ storageState: '.auth/admin.json' });
      const cleanupPage = await cleanupContext.newPage();
      await cleanupPage.goto('/');
      await cleanupPage.waitForLoadState('networkidle');
      await cleanupKeys(cleanupPage, testKeyPrefix);
      await cleanupKeys(cleanupPage, appKeyPrefix);
      await cleanupContext.close();
    });
  });
});
