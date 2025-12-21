import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false, // tests within files run serially for database isolation
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1, // sequential to avoid HTMX timing issues with shared server
  reporter: [['html', { open: 'never' }]],
  outputDir: 'test-results',

  use: {
    baseURL: 'http://localhost:18080',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'setup',
      testDir: '.',
      testMatch: /auth\.setup\.ts/,
    },
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
    },
  ],

  webServer: {
    // cleanup stale data before starting fresh server (fixes corrupted git repo issues)
    // only rebuild if binary doesn't exist or is older than source
    command: 'cd .. && rm -rf /tmp/stash-e2e.db /tmp/stash-e2e-git && ([ -f stash ] || go build -o stash ./app) && ./stash server --dbg --server.address=:18080 --db=/tmp/stash-e2e.db --auth.file=e2e/fixtures/auth.yml --git.enabled --git.path=/tmp/stash-e2e-git',
    url: 'http://localhost:18080/ping',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
