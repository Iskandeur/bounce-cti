// The `test` every spec imports. Two fixtures run for every test without being asked for:
// the mocked backend, and a guard that fails the test on an uncaught error in the page.
import { test as base, expect } from '@playwright/test'
import { mockApi } from './mockApi.js'
import { DRAWN_NODES } from './fixtures/data.js'

export const test = base.extend({
  // test.use({ authenticated: false }) makes GET /api/auth/me answer 401.
  authenticated: [true, { option: true }],

  pageErrors: [async ({ page }, use) => {
    const errors = []
    page.on('pageerror', error => errors.push(error.stack || String(error)))
    await use(errors)
    expect(errors, 'uncaught errors in the page').toEqual([])
  }, { auto: true }],

  api: [async ({ page, authenticated }, use) => {
    const api = await mockApi(page, { authenticated })
    await use(api)
    expect(api.unhandled, 'API calls the mock has no answer for').toEqual([])
  }, { auto: true }],
})

export { expect }

// The two export buttons of the graph toolbar. Their visible label flips to
// "✓ copied" after a click, so they are found by their title.
export const jsonButton = page => page.getByTitle(/as JSON/)
export const maltegoButton = page => page.getByTitle(/in Maltego paste format/)

// The canvas cannot be read from the DOM. The toolbar's "↓ JSON (N)" counts
// the nodes Cytoscape holds, so it says when the snapshot has been drawn.
export async function expectGraphDrawn(page, inv) {
  await expect(jsonButton(page)).toContainText(`↓ JSON (${DRAWN_NODES[inv]})`)
}

// A row of the History list, found by its seed value.
export const historyItem = (page, seed) =>
  page.locator('.inv-item').filter({ has: page.getByText(seed, { exact: true }) })

// Opens an investigation by a click on its name. The row's centre is no safe
// target: at phone width the Rename button sits there.
export async function openFromHistory(page, seed) {
  await historyItem(page, seed).getByText(seed, { exact: true }).click()
}

// The theme is read from localStorage before the first paint (src/main.jsx).
export async function setTheme(page, theme) {
  await page.addInitScript(t => localStorage.setItem('bounce-theme', t), theme)
}
