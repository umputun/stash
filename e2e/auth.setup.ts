import { test as setup, expect } from '@playwright/test';

const users = [
  { name: 'admin', file: '.auth/admin.json' },
  { name: 'readonly', file: '.auth/readonly.json' },
  { name: 'scoped', file: '.auth/scoped.json' },
];

for (const user of users) {
  setup(`authenticate as ${user.name}`, async ({ page }) => {
    await page.goto('/login');
    await page.fill('#username', user.name);
    await page.fill('#password', 'testpass');
    await page.click('button[type="submit"]');

    // wait for redirect to main page
    await expect(page).toHaveURL('/');
    await expect(page.locator('#keys-table')).toBeVisible();

    // save storage state
    await page.context().storageState({ path: user.file });
  });
}
