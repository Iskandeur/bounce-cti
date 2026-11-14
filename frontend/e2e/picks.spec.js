import { test, expect, expectGraphDrawn } from './harness.js'
import { INV_DOMAIN, GRAPHS } from './fixtures/data.js'

// The nodes picked for a prompt (ctrl / cmd / shift + click on the canvas) are
// a set of their own, apart from the one node the Node tab shows. Reading the
// report and walking the graph from the panel moves that one node and must
// leave the picks alone.
//
// This file clicks on the canvas, which the rest of the suite does not: the
// position of a node is asked to Cytoscape through the registration it leaves
// on its container (`_cyreg`), read just before each click, once the layout
// has come to rest.

const HASH = 'e2e0'.repeat(16)
const idOf = value => GRAPHS[INV_DOMAIN].nodes.find(n => n.value === value).id

// What Cytoscape holds: the values of the nodes with the class `picked`, and
// of the nodes in its own `:selected` state.
const canvasState = page => page.evaluate(() => {
  const cy = document.getElementById('cy')._cyreg.cy
  const values = selector => cy.nodes(selector).map(n => n.data('value')).sort()
  return { picked: values('.picked'), selected: values(':selected') }
})

// The snapshot is laid out after a 250 ms debounce, with a 500 ms animation
// (relayout in App.jsx). The canvas is at rest once no node has moved for
// longer than that debounce.
const canvasAtRest = page => page.evaluate(() => new Promise((resolve) => {
  const cy = document.getElementById('cy')._cyreg.cy
  const read = () => JSON.stringify(cy.nodes().map(n => n.renderedPosition()))
  let last = read()
  let since = performance.now()
  const tick = () => {
    const now = read()
    if (now !== last) { last = now; since = performance.now() }
    if (performance.now() - since > 700) resolve()
    else requestAnimationFrame(tick)
  }
  requestAnimationFrame(tick)
}))

async function pickOnCanvas(page, value) {
  const position = await page.evaluate((id) => {
    const cy = document.getElementById('cy')._cyreg.cy
    return cy.$id(id).renderedPosition()
  }, idOf(value))
  await page.locator('#cy').click({ position, modifiers: ['ControlOrMeta'] })
}

test.beforeEach(async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
  await canvasAtRest(page)
})

test('the nodes picked for a prompt stay picked while the panel moves from node to node', async ({ page }) => {
  const panel = page.locator('.panel-content')
  const chips = page.locator('.prompt-chip')
  const shown = panel.locator('.node-value')
  const picks = ['AS64496', HASH].sort()

  const expectPicksKept = async (selected) => {
    await expect(shown).toHaveText(selected)
    await expect(page.locator('.prompt-selected-label')).toHaveText('Selected (2):')
    await expect(chips).toHaveCount(2)
    await expect(chips.filter({ hasText: 'AS64496' })).toHaveCount(1)
    await expect(chips.filter({ hasText: HASH.slice(0, 28) })).toHaveCount(1)
    expect(await canvasState(page)).toEqual({ picked: picks, selected: [selected] })
  }

  await pickOnCanvas(page, 'AS64496')
  await expect(chips).toHaveCount(1)
  await pickOnCanvas(page, HASH)
  await expect(chips).toHaveCount(2)
  // A pick leaves the panel where it was. Cytoscape also puts a node clicked
  // with a modifier in its own `:selected` state, which focusNode clears
  // below: the picks must not depend on it.
  await expect(page.getByRole('button', { name: 'Report', exact: true })).toHaveClass(/active/)
  await expect.poll(async () => (await canvasState(page)).picked).toEqual(picks)

  // An IOC chip of the report.
  await panel.locator('.ioc-chip', { hasText: '192.0.2.10' }).click()
  await expectPicksKept('192.0.2.10')

  // A neighbour in the Node tab's Provenance: one that is not picked, then
  // one that is.
  const neighbour = name => panel.locator('.prov').getByRole('button', { name })
  await neighbour('example.com').click()
  await expectPicksKept('example.com')
  await neighbour('192.0.2.10').click()
  await expectPicksKept('192.0.2.10')
  await neighbour('AS64496').click()
  await expectPicksKept('AS64496')

  // A value highlighted in the report's text.
  await page.getByRole('button', { name: 'Report', exact: true }).click()
  await panel.locator('.ioc-link', { hasText: 'example.com' }).first().click()
  await expectPicksKept('example.com')

  // The prompt is sent with the two picks, and with them only.
  let sent = null
  await page.route(`**/api/investigations/${INV_DOMAIN}/prompt`, async (route) => {
    sent = route.request().postDataJSON()
    await route.fulfill({ json: { ok: true } })
  })
  await page.locator('.custom-prompt-input').fill('Compare these two.')
  await page.getByRole('button', { name: 'Run on 2 selected' }).click()
  await expect.poll(() => sent).not.toBeNull()
  expect(sent.selected_nodes.map(n => n.value).sort()).toEqual(picks)
})
