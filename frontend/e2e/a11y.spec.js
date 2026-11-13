import { AxeBuilder } from '@axe-core/playwright'
import { test, expect, expectGraphDrawn, setTheme } from './harness.js'
import { INV_DOMAIN } from './fixtures/data.js'
import { BASELINE } from './a11y-baseline.js'

// Runs axe-core on the page as it stands and fails on every violated rule that
// is outside `tolerated` (e2e/a11y-baseline.js, empty today).
async function expectNoNewViolation(page, tolerated = Object.keys(BASELINE)) {
  // Colours are measured at rest: the pointer off the control just clicked,
  // and every colour transition over (a tab caught half-way through its
  // transition reads as a contrast failure one run in ten).
  await page.mouse.move(0, 0)
  await page.evaluate(() => Promise.all(document.getAnimations()
    .filter(a => Number.isFinite(a.effect?.getComputedTiming().endTime))   // a looping one never ends
    .map(a => a.finished.catch(() => {}))))
  const { violations } = await new AxeBuilder({ page }).analyze()
  const unlisted = violations
    .filter(v => !tolerated.includes(v.id))
    .map(v => `${v.id} (${v.impact}): ${v.help}\n` + v.nodes.map(n => `    ${n.target.join(' ')}`).join('\n'))
  expect(unlisted, 'accessibility rules violated outside e2e/a11y-baseline.js').toEqual([])
}

for (const theme of ['dark', 'light']) {
  test(`main screen, ${theme} theme: no violation`, async ({ page }) => {
    await setTheme(page, theme)
    await page.goto(`/?inv=${INV_DOMAIN}`)
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
    await expectGraphDrawn(page, INV_DOMAIN)
    await expect(page.locator('.threat-badge')).toBeVisible()
    await expectNoNewViolation(page)
  })

  // axe checks what is drawn: each tab of the right panel is opened in turn,
  // the Node tab on a node that carries tags.
  test(`right panel tabs, ${theme} theme: no violation`, async ({ page }) => {
    await setTheme(page, theme)
    await page.goto(`/?inv=${INV_DOMAIN}`)
    await expectGraphDrawn(page, INV_DOMAIN)
    const panel = page.locator('.panel-content')
    await panel.locator('.ioc-chip', { hasText: '192.0.2.10' }).click()
    await expect(panel.locator('.node-value')).toHaveText('192.0.2.10')
    await expect(panel.locator('.tag-chip').first()).toBeVisible()
    await expectNoNewViolation(page)
    for (const tab of ['Timeline', 'Actions', 'Chat']) {
      await page.locator('.panel-tab', { hasText: tab }).click()
      await expect(page.locator('.panel-tab.active')).toHaveText(tab)
      if (tab === 'Timeline') await expect(panel.locator('.timeline-entry').first()).toBeVisible()
      await expectNoNewViolation(page)
    }
  })
}

test.describe('signed out', () => {
  test.use({ authenticated: false })

  test('login screen: no violation', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByPlaceholder('••••••')).toBeVisible()
    await expectNoNewViolation(page)
  })
})
