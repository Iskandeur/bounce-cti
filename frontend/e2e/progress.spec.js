import { test, expect, expectGraphDrawn } from './harness.js'
import { INV_DOMAIN, runningProgress } from './fixtures/data.js'

// The progress line (components/RunProgress.jsx), fed by GET …/progress. No
// run is started here: the mock answers a finished run, and a test that needs
// a live one puts its own answer on the route.
const sidebarLine = page => page.locator('.sidebar .run-progress')

async function answerProgress(page, body) {
  await page.route(`**/api/investigations/${INV_DOMAIN}/progress`, route => route.fulfill({ json: body() }))
}

test('a finished run leaves one sentence: how it ended and the calls it made', async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)

  await expect(sidebarLine(page)).toHaveText('Run finished in 12m 04s. 61 source calls of a budget of 82.')
  await expect(sidebarLine(page).getByRole('progressbar')).toHaveCount(0)
  // An investigation opened after its run ended is not announced.
  await expect(page.locator('.run-progress-live')).toHaveText('')
})

test('a live run says its phase, its length and its calls against the budget', async ({ page, api }) => {
  let phase = 'pivot_drain_2'
  await answerProgress(page, () => runningProgress(INV_DOMAIN, phase))
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)

  const line = sidebarLine(page)
  await expect(line).toContainText('Pivot drain, round 2 of at most 3')
  // The length is counted on the server's clock and ticks: 2m 05s at the answer.
  await expect(line).toContainText(/2m \d\ds into the run/)
  const bar = line.getByRole('progressbar')
  await expect(bar).toHaveAttribute('aria-valuenow', '61')
  await expect(bar).toHaveAttribute('aria-valuemax', '82')
  await expect(bar).toHaveAttribute('aria-valuetext', '61 source calls of a budget of 82')

  // A phase event on the socket asks the endpoint again, and the new phase is
  // told to assistive technology once.
  phase = 'report_write'
  api.push(INV_DOMAIN, { kind: 'phase_report_write_starting' })
  await expect(line).toContainText('Writing the report')
  await expect(page.locator('.run-progress-live')).toHaveText('Phase: Writing the report.')
})

test.describe('phone', () => {
  test.use({ viewport: { width: 375, height: 812 } })

  test('a live run shows its line under the top bar, and a finished one does not', async ({ page }) => {
    const strip = page.locator('.run-progress-topbar')

    // The run of the fixture ended a day ago: the strip stays a minute only.
    await page.goto(`/?inv=${INV_DOMAIN}`)
    await expectGraphDrawn(page, INV_DOMAIN)
    await expect(strip).toHaveCount(0)

    await answerProgress(page, () => runningProgress(INV_DOMAIN, 'followup'))
    await page.reload()
    await expectGraphDrawn(page, INV_DOMAIN)
    await expect(strip).toContainText('Follow-up')
    await expect(strip).toBeInViewport()
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375)
  })
})
