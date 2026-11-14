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
// "copied" after a click, so they are found by their title.
export const jsonButton = page => page.getByTitle(/as JSON/)
export const maltegoButton = page => page.getByTitle(/in Maltego paste format/)

// The canvas cannot be read from the DOM. The toolbar's "JSON (N)" counts
// the nodes Cytoscape holds, so it says when the snapshot has been drawn.
export async function expectGraphDrawn(page, inv) {
  await expect(jsonButton(page)).toContainText(`JSON (${DRAWN_NODES[inv]})`)
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

// Contrast of an element's text (or icon) against what is painted behind it.
// Translucent backgrounds are composited down to the page background.
export const contrast = el => el.evaluate((e) => {
  const rgba = (colour) => {
    const c = document.createElement('canvas')
    c.width = c.height = 1
    const ctx = c.getContext('2d', { willReadFrequently: true })
    ctx.fillStyle = colour
    ctx.fillRect(0, 0, 1, 1)
    const [r, g, b, a] = ctx.getImageData(0, 0, 1, 1).data
    return [r, g, b, a / 255]
  }
  const over = (top, under) => top.slice(0, 3).map((v, i) => v * top[3] + under[i] * (1 - top[3]))
  const luminance = rgb => rgb
    .map(v => v / 255)
    .map(v => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4))
    .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0)
  const layers = []
  for (let n = e; n && n.nodeType === 1; n = n.parentElement) {
    const colour = rgba(getComputedStyle(n).backgroundColor)
    if (colour[3] > 0) layers.push(colour)
  }
  let behind = rgba(getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()).slice(0, 3)
  for (const layer of layers.reverse()) behind = over(layer, behind)
  const text = over(rgba(getComputedStyle(e).color), behind)
  const [hi, lo] = [luminance(text), luminance(behind)].sort((a, b) => b - a)
  return (hi + 0.05) / (lo + 0.05)
})
