import { test, expect, expectGraphDrawn } from './harness.js'
import { INV_DOMAIN, ME } from './fixtures/data.js'

// The side panels at the narrowest width their handles allow: 180px on the
// left, 220px on the right (hooks/usePanelResize.js), restored from
// localStorage as after a drag. An admin is signed in: the sidebar header then
// holds its three buttons.
test.beforeEach(async ({ page }) => {
  await page.route('**/api/auth/me', route => route.fulfill({ json: { ...ME, is_admin: true } }))
  await page.addInitScript(() => {
    localStorage.setItem('bounce.leftWidth', '180')
    localStorage.setItem('bounce.rightWidth', '220')
  })
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
})

// How far the content of an element is wider than the element, in px.
const sidewaysScroll = locator => locator.evaluate(el => el.scrollWidth - el.clientWidth)

// The right edge of an element, against the right edge of the panel it is in.
async function expectInside(locator, panel) {
  const outer = await panel.boundingBox()
  for (const el of await locator.all()) {
    const box = await el.boundingBox()
    expect(box.x + box.width).toBeLessThanOrEqual(outer.x + outer.width + 0.5)
  }
}

test('the sidebar at 180px keeps its header buttons and the three form modes in view', async ({ page }) => {
  const sidebar = page.locator('.sidebar')
  expect((await sidebar.boundingBox()).width).toBe(180)

  expect(await sidewaysScroll(sidebar)).toBe(0)
  // Its two zones: the scrolling column, and the run of the open investigation.
  expect(await sidewaysScroll(sidebar.locator('.sidebar-main'))).toBe(0)
  expect(await sidewaysScroll(sidebar.locator('.sidebar-run'))).toBe(0)
  await expectInside(sidebar.locator('.sidebar-main button, .sidebar-main label.btn-sm, .sidebar-main input:not([hidden])'), sidebar)
  await expect(sidebar.locator('.logo-actions button')).toHaveCount(3)
  await expectInside(sidebar.locator('.logo-actions button'), sidebar)
  // IOC / Sample / PDF: three options on one row, the last one whole.
  const modes = sidebar.locator('.seg-option')
  await expect(modes).toHaveCount(3)
  await expectInside(modes, sidebar)
  const tops = await modes.evaluateAll(els => els.map(el => Math.round(el.getBoundingClientRect().top)))
  expect(new Set(tops).size).toBe(1)
  await expectInside(sidebar.locator('.inv-item button'), sidebar)
})

test('the right panel at 220px wraps its action buttons', async ({ page }) => {
  const panel = page.locator('.panel-content')
  expect(await sidewaysScroll(panel)).toBe(0)
  await expectInside(panel.locator('.export-btn'), panel)

  await panel.locator('.ioc-chip', { hasText: '192.0.2.10' }).click()
  await expect(panel.locator('.node-value')).toHaveText('192.0.2.10')
  expect(await sidewaysScroll(panel)).toBe(0)
  await expectInside(panel.getByRole('button', { name: /Pivot here|New inv|Copy JSON/ }), panel)
})

// A window between the phone layout (768px and under) and a laptop: the two
// panels cannot both keep their default width (260 and 460px) there.
test.describe('a window too narrow for both panels at their width', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.removeItem('bounce.leftWidth')
      localStorage.removeItem('bounce.rightWidth')
    })
  })

  const widths = page => page.evaluate(() => Object.fromEntries(
    ['.sidebar', '.graph', '.details'].map(sel => [sel, document.querySelector(sel).getBoundingClientRect().width])))

  for (const width of [800, 1000]) {
    test(`at ${width}px the graph keeps its room and its toolbar stays over it`, async ({ page }) => {
      await page.setViewportSize({ width, height: 800 })
      await page.goto(`/?inv=${INV_DOMAIN}`)
      await expectGraphDrawn(page, INV_DOMAIN)

      const w = await widths(page)
      expect(w['.graph']).toBeGreaterThanOrEqual(300)
      expect(w['.sidebar']).toBeGreaterThanOrEqual(180)
      expect(w['.details']).toBeGreaterThanOrEqual(220)
      expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBe(0)

      const graph = await page.locator('.graph').boundingBox()
      for (const el of await page.locator('.graph-toolbar > *').all()) {
        const box = await el.boundingBox()
        if (!box) continue   // not rendered at this width
        expect(box.x).toBeGreaterThanOrEqual(graph.x)
        expect(box.x + box.width).toBeLessThanOrEqual(graph.x + graph.width + 0.5)
      }
    })
  }

  test('at 1280px both panels have their default width', async ({ page }) => {
    await page.goto(`/?inv=${INV_DOMAIN}`)
    await expectGraphDrawn(page, INV_DOMAIN)
    const w = await widths(page)
    expect(w['.sidebar']).toBe(260)
    expect(w['.details']).toBe(460)
  })
})
