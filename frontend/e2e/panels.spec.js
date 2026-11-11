import { test, expect, expectGraphDrawn } from './harness.js'
import { INV_DOMAIN, REPORT } from './fixtures/data.js'

// The right panel. A node is never clicked on the canvas here (see README):
// it is selected through the report's IOC chips, which call the same handler.
test.beforeEach(async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
})

test('the Report tab renders the investigation summary', async ({ page }) => {
  const panel = page.locator('.panel-content')

  await expect(page.getByRole('button', { name: 'Report', exact: true })).toHaveClass(/active/)
  await expect(panel.locator('.threat-badge')).toHaveText('SUSPICIOUS')
  await expect(panel).toContainText(REPORT.summary)
  await expect(panel.locator('.finding-card')).toHaveCount(REPORT.key_findings.length)
  await expect(panel.locator('.finding-card').first()).toContainText(REPORT.key_findings[0].text)
  await expect(panel.getByRole('link', { name: 'T1583.001' }))
    .toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1583/001/')
  await expect(panel.locator('.pivot-item')).toContainText(REPORT.pivot_suggestions[0])
  await expect(panel.locator('.ioc-chip')).toHaveText(REPORT.ioc_list)

  // The aux report nodes are kept off the canvas and shown here instead.
  await expect(panel.locator('.hypothesis-card')).toContainText('phishing infrastructure')
  await expect(panel.getByText('Budget extensions (1)')).toBeVisible()
})

test('an IOC chip of the report opens the Node tab on that node', async ({ page }) => {
  const panel = page.locator('.panel-content')

  await panel.locator('.ioc-chip', { hasText: '192.0.2.10' }).click()
  await expect(page.getByRole('button', { name: 'Node', exact: true })).toHaveClass(/active/)
  await expect(panel.locator('.node-value')).toHaveText('192.0.2.10')
  await expect(panel.locator('.tag-chip').first()).toHaveText('suspicious')
  // GET …/cross_investigations: the same address is in the other investigation.
  await expect(panel.getByText('Also seen in 1 prior investigation')).toBeVisible()

  // GET …/evidence: {evidence: [{cache_key, data, cached_at}]}.
  await panel.getByRole('button', { name: 'Load' }).click()
  await expect(panel.locator('.evidence-entry')).toHaveCount(1)
  await expect(panel.locator('.evidence-entry .source-chip')).toHaveText('ip/192.0.2.10')
})

test('the Timeline tab shows the persisted transcript', async ({ page }) => {
  await page.getByRole('button', { name: 'Timeline', exact: true }).click()
  const panel = page.locator('.panel-content')
  await expect(panel.locator('.timeline-note-text')).toHaveText('Starting from the seed domain example.com.')
  await expect(panel.locator('.timeline-tool-chip')).toHaveCount(1)
})
