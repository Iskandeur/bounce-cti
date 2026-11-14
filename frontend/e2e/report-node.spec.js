import { test, expect, expectGraphDrawn } from './harness.js'
import { GRAPHS, INV_DOMAIN } from './fixtures/data.js'

// A report node (the summary, a hypothesis, a budget note) is a note of the run
// on the investigation. Its Provenance section says so; it used to read like an
// indicator the agent had forgotten to source.
// The canvas is never clicked here (see README): the summary is reached through
// an edge added to the fixture for this file, from the seed's Provenance list.
const graph = GRAPHS[INV_DOMAIN]
const edges = graph.edges
const summary = graph.nodes.find(n => n.value === 'investigation_summary')
const seed = graph.nodes.find(n => n.value === 'example.com')

test.beforeEach(() => {
  graph.edges = [...edges, {
    ...edges[0], id: `${INV_DOMAIN.slice(-4)}0000eeee0099`,
    src: summary.id, dst: seed.id, relation: 'summarises',
  }]
})
test.afterEach(() => { graph.edges = edges })

test('the Provenance of a report node says it is a note of the run', async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
  const panel = page.locator('.panel-content')
  await panel.locator('.ioc-chip', { hasText: /^example\.com$/ }).click()
  await panel.locator('section.prov').getByRole('button', { name: 'report investigation_summary' }).click()

  const prov = panel.locator('section.prov')
  await expect(prov).toContainText('during the run, as a note on the investigation. It names no source of its own.')
  await expect(prov).not.toContainText('named no source tool')
  await expect(prov).not.toContainText('No source was recorded')
})
