import { test, expect, expectGraphDrawn, jsonButton, maltegoButton } from './harness.js'
import { INV_DOMAIN, DRAWN_NODES, GRAPHS } from './fixtures/data.js'

test.beforeEach(async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
})

test.describe('graph search', () => {
  test('typing shows the match count, Escape clears', async ({ page }) => {
    const search = page.getByPlaceholder('Search IOCs…')
    const info = page.locator('.graph-search-info')

    await search.fill('192.0.2')
    await expect(info).toContainText(/^1 match(?!es)/)
    await search.fill('example.com')
    await expect(info).toContainText(/^2 matches/)
    await search.fill('no-such-name.invalid')
    await expect(info).toContainText(/^0 matches/)

    await search.press('Escape')
    await expect(search).toHaveValue('')
    await expect(info).toHaveCount(0)
  })

  // Regression for #95: Enter threw when the selected node was outside the
  // matches of the current search, and the selection then never moved.
  test('Enter walks the matches, from a selection outside them too', async ({ page }) => {
    const search = page.getByPlaceholder('Search IOCs…')
    const selected = page.locator('.node-value')

    await search.fill('192.0.2')
    await search.press('Enter')
    await expect(selected).toHaveText('192.0.2.10')

    // 192.0.2.10 stays selected and does not match the next search.
    await search.fill('example.com')
    await search.press('Enter')
    await expect(selected).toHaveText('example.com')
    await search.press('Enter')
    await expect(selected).toHaveText('mail.example.com')
    await search.press('Enter')
    await expect(selected).toHaveText('example.com')
  })
})

test.describe('copy buttons', () => {
  test.use({ permissions: ['clipboard-read', 'clipboard-write'] })

  // Regression for #94: one click used to turn every copy button to "copied".
  test('"copied" shows on the clicked button only', async ({ page }) => {
    const json = jsonButton(page)
    const maltego = maltegoButton(page)
    const copied = button => button.getByText('✓ copied')
    const clipboard = () => page.evaluate(() => navigator.clipboard.readText())

    await json.click()
    await expect(copied(json)).toBeVisible()
    // Read once, with no retry: a label that shows for 1.5 s and then goes
    // would pass an assertion that waits for it to be hidden.
    expect(await copied(maltego).isVisible()).toBe(false)
    const graph = JSON.parse(await clipboard())
    expect(graph.nodes).toHaveLength(DRAWN_NODES[INV_DOMAIN])
    expect(graph.edges).toHaveLength(GRAPHS[INV_DOMAIN].edges.length)

    // The label goes back by itself, then the other button gets its turn.
    await expect(copied(json)).toBeHidden()
    await maltego.click()
    await expect(copied(maltego)).toBeVisible()
    expect(await copied(json).isVisible()).toBe(false)
    const lines = (await clipboard()).split('\n')
    expect(lines).toContain('maltego.Domain#example.com')
    expect(lines).toContain('maltego.IPv4Address#192.0.2.10')
    // The report node has no Maltego type and is left out.
    expect(lines).toHaveLength(DRAWN_NODES[INV_DOMAIN] - 1)
  })
})
