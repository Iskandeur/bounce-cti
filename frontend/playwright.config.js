import { defineConfig, devices } from '@playwright/test'

// Browser suite of the app (e2e/README.md). No backend: Playwright starts the
// Vite dev server, and e2e/mockApi.js answers /api/ and /ws/ in the browser.
const PORT = 5199
const ORIGIN = `http://127.0.0.1:${PORT}`

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // No retry: a test that passes on the second try is a flaky test to fix.
  retries: 0,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    baseURL: ORIGIN,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    // A port of its own, and --strictPort: if it is taken the run stops, so the
    // suite can never test whatever else is listening there (another checkout).
    command: `npm run dev -- --host 127.0.0.1 --port ${PORT} --strictPort`,
    url: ORIGIN,
    reuseExistingServer: false,
    timeout: 60_000,
  },
})
