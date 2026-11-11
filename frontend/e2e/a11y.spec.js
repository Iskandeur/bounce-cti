import { AxeBuilder } from '@axe-core/playwright'
import { test, expect, expectGraphDrawn, setTheme } from './harness.js'
import { INV_DOMAIN } from './fixtures/data.js'
import { BASELINE } from './a11y-baseline.js'

// Runs axe-core on the page as it stands and fails on every violated rule that
// is outside `tolerated`. A tolerated rule that no longer fires passes: the
// agent log, for one, scrolls or not with the height of the window.
async function expectNoNewViolation(page, tolerated = Object.keys(BASELINE)) {
  const { violations } = await new AxeBuilder({ page }).analyze()
  const unlisted = violations
    .filter(v => !tolerated.includes(v.id))
    .map(v => `${v.id} (${v.impact}): ${v.help}\n` + v.nodes.map(n => `    ${n.target.join(' ')}`).join('\n'))
  expect(unlisted, 'accessibility rules violated outside e2e/a11y-baseline.js').toEqual([])
}

for (const theme of ['dark', 'light']) {
  test(`main screen, ${theme} theme: no violation outside the baseline`, async ({ page }) => {
    await setTheme(page, theme)
    await page.goto(`/?inv=${INV_DOMAIN}`)
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
    await expectGraphDrawn(page, INV_DOMAIN)
    await expect(page.locator('.threat-badge')).toBeVisible()
    await expectNoNewViolation(page)
  })
}

test.describe('signed out', () => {
  test.use({ authenticated: false })

  // The login screen breaks two of the baseline rules only: hold it to those.
  test('login screen: no violation outside the baseline', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByPlaceholder('••••••')).toBeVisible()
    await expectNoNewViolation(page, ['color-contrast', 'region'])
  })
})
