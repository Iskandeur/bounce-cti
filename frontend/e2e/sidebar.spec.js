import { test, expect, expectGraphDrawn, historyItem } from './harness.js'
import { INV_DOMAIN, INVESTIGATIONS, runningProgress } from './fixtures/data.js'

// The left panel has two zones (components/Sidebar.jsx): a column that scrolls
// (form, history, add IOC) and, at its foot, the run of the open investigation
// (progress line, agent log). These tests pin the heights: the log used to be
// the one block of a single column that could shrink, and was 14px tall in any
// window shorter than that column.
const log = page => page.getByRole('log', { name: 'Agent log' })
const height = async locator => Math.round((await locator.boundingBox()).height)

// Eight investigations, synthetic like the two of the fixture they extend: a
// history long enough to overflow the panel.
const history = status => [
  { ...INVESTIGATIONS[0], status },
  INVESTIGATIONS[1],
  ...['a', 'b', 'c', 'd', 'e', 'f'].map((label, n) => ({
    ...INVESTIGATIONS[1], id: `e2e0000001${String(n).padStart(2, '0')}`, seed_type: 'domain',
    seed_value: `${label}.example.net`, seeds: [{ type: 'domain', value: `${label}.example.net`, added_at: 0 }],
  })),
]

// Opens the fixture investigation among eight, its run live or over, with 40
// tool calls in its agent log.
async function open(page, api, { running }) {
  await page.route('**/api/investigations', route => route.fulfill({ json: history(running ? 'running' : 'done') }))
  if (running) {
    await page.route(`**/api/investigations/${INV_DOMAIN}/progress`, route =>
      route.fulfill({ json: runningProgress(INV_DOMAIN, 'pivot_drain_2') }))
  }
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
  for (let n = 0; n < 40; n++) {
    api.push(INV_DOMAIN, {
      kind: 'agent_assistant',
      msg: { message: { content: [{ type: 'tool_use', name: 'mcp__cti__dns_resolve', input: { domain: `host-${n}.example.com` } }] } },
    })
  }
  await expect(log(page).locator('.event-line.tool')).toHaveCount(40)
}

test.describe('a laptop-height window, 1280x600', () => {
  test.use({ viewport: { width: 1280, height: 600 } })

  test('during a run the agent log keeps seven lines or more, in view with the progress line', async ({ page, api }) => {
    await open(page, api, { running: true })

    expect(await height(log(page))).toBeGreaterThanOrEqual(132)
    await expect(log(page)).toBeInViewport({ ratio: 1 })
    await expect(page.locator('.sidebar .run-progress')).toBeInViewport({ ratio: 1 })
    // The log scrolls on its own, and the column above it too: the panel never does.
    expect(await log(page).evaluate(el => el.scrollHeight > el.clientHeight)).toBe(true)
    expect(await page.locator('.sidebar-main').evaluate(el => el.scrollHeight > el.clientHeight)).toBe(true)
    expect(await page.locator('.sidebar').evaluate(el => el.scrollHeight - el.clientHeight)).toBe(0)
    // History keeps about three rows, and the form above it is not squeezed.
    expect(await height(page.locator('.inv-list'))).toBeGreaterThanOrEqual(200)
    expect(await height(page.locator('.batch-textarea'))).toBeGreaterThanOrEqual(60)
  })

  test('once the run is over the log is shorter, and still in view', async ({ page, api }) => {
    await open(page, api, { running: false })

    const h = await height(log(page))
    expect(h).toBeGreaterThanOrEqual(72)
    expect(h).toBeLessThanOrEqual(132)
    await expect(log(page)).toBeInViewport({ ratio: 1 })
  })

  test('with no investigation open there is no agent log, and a short history is as tall as its rows', async ({ page }) => {
    await page.goto('/')
    await expect(historyItem(page, 'example.com')).toBeVisible()

    await expect(page.getByRole('log')).toHaveCount(0)
    await expect(page.locator('.sidebar-run')).toHaveCount(0)
    const rows = await page.locator('.inv-item').evaluateAll(els => els.reduce((sum, el) => sum + el.getBoundingClientRect().height, 0))
    expect(await height(page.locator('.inv-list'))).toBeLessThanOrEqual(Math.ceil(rows) + 8)
  })

  test('the field of "Add IOC" takes the row, its button the width of its label', async ({ page, api }) => {
    await open(page, api, { running: false })

    const field = await page.getByPlaceholder('Paste any IOC (auto-detected)').boundingBox()
    const button = await page.getByRole('button', { name: '+ Add' }).boundingBox()
    expect(field.width).toBeGreaterThan(button.width * 2)
  })
})

test.describe('phone', () => {
  test.use({ viewport: { width: 375, height: 812 } })

  test('the drawer scrolls as one column: history keeps its rows and the log its height', async ({ page, api }) => {
    await open(page, api, { running: true })
    await page.getByRole('button', { name: 'Toggle sidebar' }).click()
    await expect(page.locator('.sidebar')).toBeInViewport()

    // Both used to shrink to nothing in a drawer shorter than its content.
    expect(await height(page.locator('.inv-list'))).toBeGreaterThanOrEqual(200)
    expect(await height(log(page))).toBeGreaterThanOrEqual(132)
    const sidebar = page.locator('.sidebar')
    expect(await sidebar.evaluate(el => el.scrollHeight > el.clientHeight)).toBe(true)
    expect(await sidebar.evaluate(el => el.scrollWidth - el.clientWidth)).toBe(0)
    await log(page).scrollIntoViewIfNeeded()
    await expect(log(page)).toBeInViewport({ ratio: 1 })
  })
})
