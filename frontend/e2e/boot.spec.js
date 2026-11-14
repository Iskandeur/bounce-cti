import { test, expect, expectGraphDrawn, historyItem, openFromHistory, jsonButton } from './harness.js'
import { INV_DOMAIN, INV_IP, DRAWN_NODES } from './fixtures/data.js'

test.describe('signed in', () => {
  test('the history lists the investigations, and opening one draws its graph', async ({ page }) => {
    await page.goto('/')
    await expect(historyItem(page, 'example.com')).toBeVisible()
    await expect(historyItem(page, '192.0.2.10')).toBeVisible()
    await expect(jsonButton(page)).toBeDisabled()

    await openFromHistory(page, 'example.com')
    // 10 nodes in the snapshot, 7 drawn: working_hypothesis, budget_extension_1
    // and lessons_learned stay out of the canvas.
    await expectGraphDrawn(page, INV_DOMAIN)
    await expect(historyItem(page, 'example.com')).toHaveClass(/active/)
    await expect(jsonButton(page)).toBeEnabled()
  })

  test('opening another investigation replaces the graph', async ({ page }) => {
    await page.goto('/')
    await openFromHistory(page, 'example.com')
    await expectGraphDrawn(page, INV_DOMAIN)
    await openFromHistory(page, '192.0.2.10')
    await expectGraphDrawn(page, INV_IP)
  })

  test('a node sent on the WebSocket is added to the graph', async ({ page, api }) => {
    await page.goto('/')
    await openFromHistory(page, '192.0.2.10')
    await expectGraphDrawn(page, INV_IP)

    api.push(INV_IP, {
      kind: 'node_added',
      node: {
        id: '0002000000000099', investigation_id: INV_IP, type: 'domain', value: 'new.example.com',
        metadata: {}, tags: [], confidence: 0.8, source: 'agent', created_at: 1767229200,
      },
    })
    await expect(jsonButton(page)).toContainText(`JSON (${DRAWN_NODES[INV_IP] + 1})`)
  })
})

test.describe('signed out', () => {
  test.use({ authenticated: false })

  test('the PIN login screen is shown', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByText('Sign in', { exact: true }).first()).toBeVisible()
    await expect(page.getByPlaceholder('••••••')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeDisabled()
    await expect(page.locator('.inv-list')).toHaveCount(0)
  })
})
