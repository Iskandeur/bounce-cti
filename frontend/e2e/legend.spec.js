import { test, expect, expectGraphDrawn, jsonButton } from './harness.js'
import { INV_DOMAIN, DRAWN_NODES } from './fixtures/data.js'

// The legend and the "Defused" toggle of the canvas. Both are read from the
// DOM. Whether a node is drawn on the canvas is not (see README).
test.beforeEach(async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
})

test('the legend lists the node types of this graph with their counts', async ({ page }) => {
  const toggle = page.getByRole('button', { name: 'Legend' })
  const legend = page.getByRole('region', { name: 'Graph legend' })
  const count = type => legend.locator('li')
    .filter({ has: page.getByText(type, { exact: true }) })
    .locator('.graph-legend-count')

  await expect(legend).toHaveCount(0)
  await toggle.click()
  await expect(toggle).toHaveAttribute('aria-expanded', 'true')
  await expect(count('domain')).toHaveText('2')
  await expect(count('ip')).toHaveText('2')
  await expect(count('asn')).toHaveText('1')
  await expect(count('hash')).toHaveText('1')
  await expect(count('investigation summary')).toHaveText('1')
  // A type the graph does not hold has no line.
  await expect(legend.getByText('url', { exact: true })).toHaveCount(0)

  await page.keyboard.press('Escape')
  await expect(legend).toHaveCount(0)
  await expect(toggle).toHaveAttribute('aria-expanded', 'false')
})

test('the Defused toggle counts the defused nodes, and exports keep every node', async ({ page }) => {
  // One node of the fixture carries a defuse tag: 198.51.100.7, tagged cdn.
  const on = page.getByRole('button', { name: '◌ Defused on (1)' })
  const off = page.getByRole('button', { name: '◌ Defused off (1)' })

  await expect(on).toHaveAttribute('aria-pressed', 'true')
  await on.click()
  await expect(off).toHaveAttribute('aria-pressed', 'false')
  await expect(jsonButton(page)).toContainText(`↓ JSON (${DRAWN_NODES[INV_DOMAIN]})`)
  await off.click()
  await expect(on).toHaveAttribute('aria-pressed', 'true')
})
