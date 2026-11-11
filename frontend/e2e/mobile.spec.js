import { test, expect, expectGraphDrawn, historyItem, openFromHistory, jsonButton, maltegoButton } from './harness.js'
import { INV_DOMAIN } from './fixtures/data.js'

// A phone in portrait. Below 768px the sidebar and the right panel become
// drawers, opened from the top bar.
test.use({ viewport: { width: 375, height: 812 } })

const scrollsSideways = page => page.evaluate(() => {
  const root = document.documentElement
  return root.scrollWidth > root.clientWidth
})

test('the top bar opens each drawer, a tap outside closes it', async ({ page }) => {
  const sidebarToggle = page.getByRole('button', { name: 'Toggle sidebar' })
  const detailsToggle = page.getByRole('button', { name: 'Toggle details panel' })
  // The backdrop covers everything but the open drawer, the top bar included.
  const backdrop = page.locator('.mobile-backdrop')

  await page.goto('/')
  await expect(sidebarToggle).toHaveAttribute('aria-expanded', 'false')
  await expect(page.locator('.sidebar')).not.toBeInViewport()
  expect(await scrollsSideways(page)).toBe(false)

  await sidebarToggle.click()
  await expect(sidebarToggle).toHaveAttribute('aria-expanded', 'true')
  await expect(historyItem(page, 'example.com')).toBeInViewport()
  await backdrop.click({ position: { x: 360, y: 400 } })
  await expect(sidebarToggle).toHaveAttribute('aria-expanded', 'false')
  await expect(page.locator('.sidebar')).not.toBeInViewport()

  await detailsToggle.click()
  await expect(detailsToggle).toHaveAttribute('aria-expanded', 'true')
  await expect(page.getByRole('button', { name: 'Report', exact: true })).toBeInViewport()
  await backdrop.click({ position: { x: 15, y: 400 } })
  await expect(detailsToggle).toHaveAttribute('aria-expanded', 'false')
  await expect(page.locator('.details')).not.toBeInViewport()
})

test('opening an investigation closes the sidebar and shows the graph', async ({ page }) => {
  const sidebarToggle = page.getByRole('button', { name: 'Toggle sidebar' })

  await page.goto('/')
  await sidebarToggle.click()
  await openFromHistory(page, 'example.com')
  await expect(sidebarToggle).toHaveAttribute('aria-expanded', 'false')
  await expect(page.locator('.sidebar')).not.toBeInViewport()
  await expectGraphDrawn(page, INV_DOMAIN)

  // The toolbar buttons share one row that scrolls on its own: a button past
  // the right edge is reached by scrolling the row, and the page stays put.
  await jsonButton(page).scrollIntoViewIfNeeded()
  await expect(jsonButton(page)).toBeInViewport()
  await expect(maltegoButton(page)).toBeHidden()
  expect(await scrollsSideways(page)).toBe(false)

  await page.getByRole('button', { name: 'Toggle details panel' }).click()
  await expect(page.locator('.threat-badge')).toBeInViewport()
  expect(await scrollsSideways(page)).toBe(false)
})

test('the graph search keeps its width and the buttons stay on one row', async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)

  // The search field has a row to itself: it used to be squeezed to two letters.
  const search = await page.getByPlaceholder('Search IOCs…').boundingBox()
  expect(search.width).toBeGreaterThan(300)

  const tops = await page.locator('.graph-toolbar .toolbar-btn').evaluateAll(
    buttons => [...new Set(buttons.filter(b => b.offsetParent).map(b => Math.round(b.getBoundingClientRect().top)))])
  expect(tops, 'tops of the toolbar buttons').toHaveLength(1)
  expect(tops[0]).toBeGreaterThan(search.y + search.height - 1)
})

// Every element that shows text of its own, with the size it is drawn at.
const smallText = page => page.evaluate(() => {
  const found = new Set()
  for (const el of document.querySelectorAll('body *')) {
    const own = [...el.childNodes].some(n => n.nodeType === Node.TEXT_NODE && n.textContent.trim())
    if (!own || !el.getClientRects().length) continue
    const style = getComputedStyle(el)
    if (style.visibility === 'hidden') continue
    const size = parseFloat(style.fontSize)
    if (size < 11) found.add(`${el.className || el.tagName} ${size}px`)
  }
  return [...found]
})

test('no text is drawn under 11px', async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
  expect(await smallText(page), 'graph and toolbar').toEqual([])

  await page.getByRole('button', { name: 'Toggle sidebar' }).click()
  await expect(page.locator('.sidebar')).toBeInViewport()
  expect(await smallText(page), 'sidebar').toEqual([])
  await page.locator('.mobile-backdrop').click({ position: { x: 360, y: 400 } })

  await page.getByRole('button', { name: 'Toggle details panel' }).click()
  await expect(page.locator('.threat-badge')).toBeInViewport()
  expect(await smallText(page), 'report').toEqual([])
})
