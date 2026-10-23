import { defineConfig, devices } from '@playwright/test';

const PORT = 4321;

export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: '*.spec.mjs',
  timeout: 60_000,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [['list']],
  use: {
    baseURL: `http://localhost:${PORT}`,
    ...devices['Desktop Chrome'],
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
  webServer: {
    // `npm test` builds first, so the preview serves the same dist/ the tests read their routes from.
    command: `npx astro preview --port ${PORT} --host localhost`,
    url: `http://localhost:${PORT}/blastradius/`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
