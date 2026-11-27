import { test, expect, expectGraphDrawn, setTheme, historyItem, contrast } from './harness.js'
import { INV_DOMAIN, INV_IP, DRAWN_NODES } from './fixtures/data.js'

// The rules every button follows (src/lib/icons.js says which take an icon;
// src/lib/icons.test.js checks the sources). Here they are measured on the
// rendered page.

// Everything a reader can press. A <label> stands for its hidden file input.
const PRESSABLE = 'button, a[href], [role="button"], label[for$="-input"]'

// The <span> of an IOC inside a sentence, and a neighbour named in a line of
// the Provenance section: WCAG 2.5.8 leaves out a target that sits in a line
// of text, whose height is the line's.
const INLINE = '.ioc-link, .prov-link'

async function openNodeTab(page) {
  const panel = page.locator('.panel-content')
  await panel.locator('.ioc-chip', { hasText: '192.0.2.10' }).click()
  await expect(panel.locator('.node-value')).toHaveText('192.0.2.10')
}

test.beforeEach(async ({ page }) => {
  // States are read as they end, not half-way through a colour transition.
  await page.addInitScript(() => {
    document.addEventListener('DOMContentLoaded', () => {
      const style = document.createElement('style')
      style.textContent = '*, *::before, *::after { transition: none !important; }'
      document.head.append(style)
    })
  })
})

for (const viewport of [{ width: 1440, height: 900 }, { width: 375, height: 812 }]) {
  test(`at ${viewport.width}px every control has a name and at least 24x24px to press`, async ({ page }) => {
    await page.setViewportSize(viewport)
    await page.goto(`/?inv=${INV_DOMAIN}`)
    await expectGraphDrawn(page, INV_DOMAIN)
    if (viewport.width < 769) await page.getByRole('button', { name: 'Toggle details panel' }).click()
    await expect(page.locator('.threat-badge')).toBeVisible()

    const check = async (where) => {
      const found = await page.locator(PRESSABLE).evaluateAll((els, inline) => els
        .filter(e => e.checkVisibility({ visibilityProperty: true }))
        .map((e) => {
          const box = e.getBoundingClientRect()
          return {
            what: `${e.tagName.toLowerCase()}.${e.className} "${e.innerText.trim().slice(0, 24)}"`,
            name: (e.getAttribute('aria-label') || e.innerText).trim(),
            glyph: /[←-⇿⌀-⏿■-⟿⤀-⯿]|\p{Extended_Pictographic}/u.test(e.innerText),
            small: !e.matches(inline) && (box.width < 23.5 || box.height < 23.5),
            icons: [...e.querySelectorAll('svg')].filter(s => s.getAttribute('aria-hidden') !== 'true').length,
          }
        }), INLINE)
      expect(found.length, `${where}: controls found`).toBeGreaterThan(8)
      expect(found.filter(f => !f.name).map(f => f.what), `${where}: no accessible name`).toEqual([])
      expect(found.filter(f => f.glyph).map(f => f.what), `${where}: a glyph or an emoji in a label`).toEqual([])
      expect(found.filter(f => f.icons).map(f => f.what), `${where}: an icon not hidden from assistive technology`).toEqual([])
      // The MITRE technique id is a link alone at the start of its row: under
      // 24px high, with no other target within 24px (the spacing exception).
      expect(found.filter(f => f.small && !f.what.startsWith('a.mitre-id')).map(f => f.what),
        `${where}: under 24x24px`).toEqual([])
    }
    await check('Report tab')
    await openNodeTab(page)
    await check('Node tab')
    for (const tab of ['Timeline', 'Actions', 'Chat']) {
      await page.getByRole('button', { name: tab, exact: true }).click()
      await check(`${tab} tab`)
    }
  })
}

test('a toggle keeps its label, and says its state with aria-pressed and a ticked box', async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
  for (const name of ['Labels', 'Pins', 'Notes', 'Defused (1)']) {
    const toggle = page.getByRole('button', { name, exact: true })
    const [pressed, width] = [await toggle.getAttribute('aria-pressed'), (await toggle.boundingBox()).width]
    const box = () => toggle.locator('svg path').count()   // the tick is a second path
    const paths = await box()
    await toggle.click()
    await expect(toggle).toHaveAttribute('aria-pressed', pressed === 'true' ? 'false' : 'true')
    expect(await box(), `${name}: the box changes with the state`).not.toBe(paths)
    expect((await toggle.boundingBox()).width, `${name}: same width in both states`).toBe(width)
    await toggle.click()
    await expect(toggle).toHaveAttribute('aria-pressed', pressed)
  }
  // A filter chip is a toggle too, the edge-relation ones included.
  const chip = page.locator('.relation-chip').first()
  await expect(chip).toHaveAttribute('aria-pressed', 'true')
  await chip.click()
  await expect(chip).toHaveAttribute('aria-pressed', 'false')
})

test('keyboard focus draws a 2px ring on a button, a chip and a file picker', async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
  const ring = el => el.evaluate(e => {
    const s = getComputedStyle(e)
    return `${s.outlineStyle} ${s.outlineWidth}`
  })
  // Tab from the search field lands on the first toolbar button.
  await page.getByLabel('Search the graph').focus()
  await page.keyboard.press('Tab')
  const fit = page.getByRole('button', { name: 'Fit', exact: true })
  await expect(fit).toBeFocused()
  expect(await ring(fit)).toBe('solid 2px')

  const chip = page.locator('.panel-content .ioc-chip.clickable').first()
  await chip.focus()
  await page.keyboard.press('Shift+Tab')
  await page.keyboard.press('Tab')
  await expect(chip).toBeFocused()
  expect(await ring(chip)).toBe('solid 2px')

  // The PDF picker of the sidebar: the input is hidden, its label shows the ring.
  const picker = page.locator('#pdf-add-seed-input')
  await picker.focus()
  await page.keyboard.press('Shift+Tab')
  await page.keyboard.press('Tab')
  await expect(picker).toBeFocused()
  expect(await ring(page.locator('label[for="pdf-add-seed-input"]'))).toBe('solid 2px')
})

test('the history and the IOC chips work from the keyboard', async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
  await historyItem(page, '192.0.2.10').getByRole('button', { name: '192.0.2.10', exact: true }).focus()
  await page.keyboard.press('Enter')
  await expectGraphDrawn(page, INV_IP)
  expect(DRAWN_NODES[INV_IP]).not.toBe(DRAWN_NODES[INV_DOMAIN])

  await historyItem(page, 'example.com').getByRole('button', { name: 'example.com', exact: true }).focus()
  await page.keyboard.press('Enter')
  await expectGraphDrawn(page, INV_DOMAIN)
  const panel = page.locator('.panel-content')
  await panel.getByRole('button', { name: '192.0.2.10', exact: true }).last().focus()
  await page.keyboard.press('Enter')
  await expect(panel.locator('.node-value')).toHaveText('192.0.2.10')
})

test('a disabled button is dimmed and does not answer the pointer', async ({ page }) => {
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
  // Nothing typed yet: "Investigate" and "Add" are disabled.
  for (const name of ['Investigate', 'Add']) {
    const button = page.getByRole('button', { name, exact: true })
    await expect(button).toBeDisabled()
    const look = () => button.evaluate((e) => {
      const s = getComputedStyle(e)
      return [s.opacity, s.backgroundColor, s.color, s.cursor].join(' ')
    })
    const rest = await look()
    expect(Number(rest.split(' ')[0]), `${name}: dimmed`).toBeLessThan(0.6)
    expect(rest.endsWith('not-allowed')).toBe(true)
    await button.hover({ force: true })
    expect(await look(), `${name}: no hover state`).toBe(rest)
  }
})

for (const theme of ['dark', 'light']) {
  test(`${theme} theme: hovered, a control stays readable`, async ({ page }) => {
    await setTheme(page, theme)
    await page.goto(`/?inv=${INV_DOMAIN}`)
    await expectGraphDrawn(page, INV_DOMAIN)
    await page.getByLabel('Search the graph').fill('example')
    await openNodeTab(page)
    // Text needs 4.5:1 (WCAG 1.4.3), an icon alone 3:1 (1.4.11).
    const groups = [
      ['.graph-toolbar button', null],
      ['.filter-bars button', null],
      ['.inv-item .icon-btn', 3],
      ['.logo-actions button', 3],
      ['.panel-tabs button', null],
      ['.panel-content button', null],
    ]
    const weak = []
    for (const [selector, floor] of groups) {
      const controls = await page.locator(selector).all()
      expect(controls.length, selector).toBeGreaterThan(0)
      for (const control of controls) {
        if (!(await control.isVisible()) || await control.isDisabled()) continue
        const iconOnly = (await control.innerText()).trim() === ''
        const needed = floor ?? (iconOnly ? 3 : 4.5)
        const rest = await contrast(control)
        await control.hover()
        const hovered = await contrast(control)
        const label = await control.evaluate(e => e.getAttribute('aria-label') || e.innerText.trim())
        if (rest < needed) weak.push(`${label}: ${rest.toFixed(2)}:1 at rest`)
        if (hovered < needed) weak.push(`${label}: ${hovered.toFixed(2)}:1 hovered`)
      }
    }
    expect(weak).toEqual([])
  })
}
