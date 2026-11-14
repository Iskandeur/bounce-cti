import { test, expect, expectGraphDrawn, setTheme, contrast, jsonButton } from './harness.js'
import { INV_DOMAIN, ME } from './fixtures/data.js'

// The look of the buttons (the "Buttons" block of src/styles.css): a neutral
// outline, one filled button per panel, red ink for what destroys, and two
// animations tied to an event (the check mark of "copied", the line under a
// busy button). Names, sizes, focus ring and the disabled look are in
// buttons.spec.js.

const USERS = {
  all_models: ['sonnet', 'opus'],
  users: [
    { id: 1, label: 'Admin', is_admin: true, created_at: 1767225600, allowed_models: [], stats: { total: 2 }, investigations: [] },
    { id: 2, label: 'Analyst', is_admin: false, created_at: 1767225600, allowed_models: ['sonnet'], stats: { total: 1 }, investigations: [] },
  ],
}
const SHARES = [{ token: 'tok-e2e-1', label: 'SOC partner', sections: ['graph', 'report'], created_at: 1767225600, expires_at: null, revoked: false, views: 0 }]

// What the share dialog, the admin panel and the Actions tab ask for.
async function mockDialogs(page) {
  await page.route('**/api/auth/me', route => route.fulfill({ json: { ...ME, is_admin: true } }))
  await page.route('**/api/admin/users', route => route.fulfill({ json: USERS }))
  await page.route('**/api/investigations/*/shares', route => route.fulfill({ json: SHARES }))
  await page.route('**/api/investigations/*/actions/blocklist**', route =>
    route.fulfill({ json: { content: 'example.com\n192.0.2.10\n', filename: 'blocklist.txt' } }))
}

async function open(page, theme = 'dark') {
  await setTheme(page, theme)
  await mockDialogs(page)
  await page.goto(`/?inv=${INV_DOMAIN}`)
  await expectGraphDrawn(page, INV_DOMAIN)
}

async function openNodeTab(page) {
  const panel = page.locator('.panel-content')
  await panel.locator('.ioc-chip', { hasText: '192.0.2.10' }).click()
  await expect(panel.locator('.node-value')).toHaveText('192.0.2.10')
}

// The visible buttons and links of `scope` that are painted in the accent
// colour, whatever class they carry: their labels.
const filled = scope => scope.locator('button, a, label').evaluateAll((els) => {
  const probe = document.createElement('i')
  probe.style.color = 'var(--primary)'
  document.body.append(probe)
  const accent = getComputedStyle(probe).color
  probe.remove()
  return els
    .filter(e => e.checkVisibility({ visibilityProperty: true }) && getComputedStyle(e).backgroundColor === accent)
    .map(e => (e.getAttribute('aria-label') || e.innerText).trim())
})

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

test('each panel and each dialog has one filled button, and the graph has none', async ({ page }) => {
  await open(page)
  const sidebar = page.locator('.sidebar')
  const details = page.locator('.details')
  expect(await filled(sidebar)).toEqual(['Investigate'])
  // Batch mode shows a switch: on, it is an outline like any toggle.
  await sidebar.getByRole('textbox').first().fill('example.org\nexample.net')
  await sidebar.getByRole('button', { name: /^Combined/ }).click()
  expect(await filled(sidebar)).toEqual(['Launch 2 IOCs'])
  expect(await filled(page.locator('.graph'))).toEqual([])

  expect(await filled(details), 'Report tab').toEqual(['Run prompt'])
  await openNodeTab(page)
  expect(await filled(details), 'Node tab').toEqual(['Run prompt'])
  await page.getByRole('button', { name: 'Timeline', exact: true }).click()
  expect(await filled(details), 'Timeline tab').toEqual(['Run prompt'])
  await page.getByRole('button', { name: 'Actions', exact: true }).click()
  await page.getByRole('button', { name: /^Blocklist/ }).click()
  await expect(page.getByRole('button', { name: 'Plain text' })).toHaveAttribute('aria-pressed', 'true')
  expect(await filled(details), 'Actions tab').toEqual(['Run prompt'])
  await page.getByRole('button', { name: 'Chat', exact: true }).click()
  expect(await filled(details), 'Chat tab').toEqual(['Send'])

  await page.getByRole('button', { name: 'Report', exact: true }).click()
  await page.getByRole('button', { name: 'Share', exact: true }).click()
  const share = page.locator('.share-modal')
  await expect(share.getByRole('button', { name: 'Revoke' })).toBeVisible()
  expect(await filled(share)).toEqual(['Create a link and copy it'])
  await share.getByRole('button', { name: 'Close' }).click()

  await page.locator('.admin-btn').click()
  const admin = page.locator('.admin-modal')
  await admin.getByText('Analyst').click()
  await expect(admin.getByRole('button', { name: 'Delete user and all their data' })).toBeVisible()
  expect(await filled(admin)).toEqual(['Create user & generate PIN'])
})

test.describe('signed out', () => {
  test.use({ authenticated: false })
  test('the login screen has one filled button', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
    expect(await filled(page.locator('body'))).toEqual(['Sign in'])
  })
})

test('hovered or pressed, a button stays where it is', async ({ page }) => {
  await open(page)
  await openNodeTab(page)
  await page.locator('.custom-prompt-input').fill('look again')
  const box = b => b.evaluate((e) => {
    const r = e.getBoundingClientRect()
    return [r.x, r.y, r.width, r.height, getComputedStyle(e).transform, getComputedStyle(e).boxShadow].join(' ')
  })
  const moved = []
  for (const selector of ['.graph-toolbar button', '.inv-item .icon-btn', '.logo-actions button', '.panel-content button', '.details .btn-primary', '.sidebar .btn-lead']) {
    for (const button of await page.locator(selector).all()) {
      if (!(await button.isVisible()) || await button.isDisabled()) continue
      // hover() may scroll the button into view, so the state at rest is read
      // last, once the pointer has left: no scroll happens in between.
      await button.hover()
      const hovered = await box(button)
      await page.mouse.down()
      const pressed = await box(button)
      // Released off the button: no click, so nothing is copied, pinned or sent.
      await page.mouse.move(0, 0)
      await page.mouse.up()
      const rest = await box(button)
      const label = await button.evaluate(e => e.getAttribute('aria-label') || e.innerText.trim())
      if (hovered !== rest) moved.push(`${label}: hovered ${hovered}, at rest ${rest}`)
      if (pressed !== rest) moved.push(`${label}: pressed ${pressed}, at rest ${rest}`)
      expect(rest.endsWith('none none'), `${label}: no transform, no shadow`).toBe(true)
    }
  }
  expect(moved).toEqual([])
})

// Text needs 4.5:1 (WCAG 1.4.3) in every state a button can be read in.
for (const theme of ['dark', 'light']) {
  test(`${theme} theme: every kind of button reads at 4.5:1, at rest, hovered and pressed`, async ({ page }) => {
    await open(page, theme)
    await openNodeTab(page)
    await page.locator('.custom-prompt-input').fill('look again')
    const figures = {}
    // The pointer is released off the button, so nothing is clicked. In a
    // dialog it is parked on the title: a release on the backdrop closes it.
    const measure = async (name, button, { press = true, park } = {}) => {
      const away = () => (park ? park.hover() : page.mouse.move(0, 0))
      await away()
      figures[name] = await contrast(button)
      await button.hover()
      figures[`${name}, hovered`] = await contrast(button)
      if (press) {
        await page.mouse.down()
        figures[`${name}, pressed`] = await contrast(button)
        await away()
        await page.mouse.up()
      }
    }
    const details = page.locator('.details')
    await measure('primary', details.getByRole('button', { name: 'Run prompt' }))
    await measure('lead', details.getByRole('button', { name: 'Pivot here' }))
    await measure('neutral', details.getByRole('button', { name: 'New inv' }))
    await measure('toolbar', page.getByRole('button', { name: 'Fit', exact: true }))
    const labels = page.getByRole('button', { name: 'Labels', exact: true })
    await expect(labels).toHaveAttribute('aria-pressed', 'true')
    await measure('toolbar toggle, on', labels)
    await measure('icon', page.locator('.inv-item .icon-btn[aria-label="Rename"]').first())
    await measure('icon, destructive', page.locator('.inv-item .icon-btn.danger').first())

    await page.getByRole('button', { name: 'Actions', exact: true }).click()
    await page.getByRole('button', { name: /^Blocklist/ }).click()
    await measure('format in use', page.getByRole('button', { name: 'Plain text' }), { press: false })

    await page.getByRole('button', { name: 'Report', exact: true }).click()
    await page.getByRole('button', { name: 'Share', exact: true }).click()
    const share = page.locator('.share-modal')
    let park = share.getByRole('heading')
    await measure('primary, in a dialog', share.getByRole('button', { name: 'Create a link and copy it' }), { park })
    await measure('destructive, small', share.getByRole('button', { name: 'Revoke' }), { park })
    await share.getByRole('button', { name: 'Close' }).click()

    await page.locator('.admin-btn').click()
    const admin = page.locator('.admin-modal')
    await admin.getByText('Analyst').click()
    park = admin.getByText('Allowed models (unchecked = no restriction):')
    await measure('destructive', admin.getByRole('button', { name: 'Delete user and all their data' }), { park })
    await measure('neutral, in a dialog', admin.getByRole('button', { name: 'Log in as this user' }), { park })

    const weak = Object.entries(figures)
      // An icon alone needs 3:1 (WCAG 1.4.11).
      .filter(([name, ratio]) => ratio < (name.startsWith('icon') ? 3 : 4.5))
      .map(([name, ratio]) => `${name}: ${ratio.toFixed(2)}:1`)
    // PRINT_CONTRAST=1 prints the figures, for a pull request or a new colour.
    if (process.env.PRINT_CONTRAST) console.log(theme, JSON.stringify(figures, (k, v) => typeof v === 'number' ? Number(v.toFixed(2)) : v, 1))
    expect(weak).toEqual([])
  })
}

test.describe('copied', () => {
  test.use({ permissions: ['clipboard-read', 'clipboard-write'] })
  const tick = button => button.locator('.icon.tick-draw path')
  const style = path => path.evaluate((e) => {
    const s = getComputedStyle(e)
    return { name: s.animationName, seconds: parseFloat(s.animationDuration), offset: parseFloat(s.strokeDashoffset) }
  })

  test('the check mark draws itself in 180ms, once', async ({ page }) => {
    await open(page)
    const json = jsonButton(page)
    await expect(tick(json)).toHaveCount(0)
    await json.click()
    await expect(json.getByText('copied')).toBeVisible()
    const drawn = await style(tick(json))
    expect(drawn.name).toBe('btn-tick')
    expect(drawn.seconds).toBeCloseTo(0.18)
    // The stroke ends fully drawn and stays so.
    await expect.poll(async () => (await style(tick(json))).offset).toBe(0)
    // Back to its label, the button holds no running animation.
    await expect(json.getByText('copied')).toBeHidden()
    await expect(tick(json)).toHaveCount(0)
  })

  test('under reduced motion the check mark is there at once', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await open(page)
    const json = jsonButton(page)
    await json.click()
    await expect(json.getByText('copied')).toBeVisible()
    expect(await style(tick(json))).toEqual({ name: 'none', seconds: 0, offset: 0 })
  })
})

test.describe('busy', () => {
  // The line under the label: the ::after of the busy element.
  const line = el => el.evaluate((e) => {
    const s = getComputedStyle(e, '::after')
    return { content: s.content, name: s.animationName, height: s.height }
  })
  const PDF = { name: 'report.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4\n') }

  // "Import a PDF" is as wide as its label, so it is the one whose width a
  // longer busy label could change.
  async function startImport(page) {
    let release
    const held = new Promise((resolve) => { release = resolve })
    await page.route('**/api/investigations/*/from_pdf', async (route) => {
      await held
      await route.fulfill({ json: { filename: 'report.pdf', seeds_queued: 0 } })
    })
    const label = page.locator('label[for="pdf-add-seed-input"]')
    const width = (await label.boundingBox()).width
    await expect(label).not.toHaveAttribute('aria-busy', 'true')
    await page.locator('#pdf-add-seed-input').setInputFiles(PDF)
    await expect(label).toHaveAttribute('aria-busy', 'true')
    return { label, width, release }
  }

  test('a busy button changes its label, keeps its width, and runs a line under it', async ({ page }) => {
    await open(page)
    const { label, width, release } = await startImport(page)
    await expect(label.getByText('Reading the PDF…')).toBeVisible()
    await expect(label.getByText('Import a PDF')).toBeHidden()
    expect((await label.boundingBox()).width, 'same width while busy').toBe(width)
    expect(await line(label)).toEqual({ content: '""', name: 'btn-busy', height: '2px' })
    release()
    await expect(label).not.toHaveAttribute('aria-busy', 'true')
    await expect(label.getByText('Import a PDF')).toBeVisible()
    expect((await label.boundingBox()).width, 'same width afterwards').toBe(width)
    expect((await line(label)).content).toBe('none')
  })

  test('under reduced motion the line stands still', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await open(page)
    const { label, release } = await startImport(page)
    expect(await line(label)).toEqual({ content: '""', name: 'none', height: '2px' })
    release()
    await expect(label).not.toHaveAttribute('aria-busy', 'true')
  })

  test('the prompt button is busy while the agent works: not dimmed, and deaf to a second press', async ({ page }) => {
    await open(page)
    let sent = 0
    await page.route('**/api/investigations/*/prompt', (route) => { sent++; return route.fulfill({ json: { ok: true } }) })
    await page.locator('.custom-prompt-input').fill('look again')
    await page.getByRole('button', { name: 'Run prompt' }).click()
    // The prompt opens the Chat tab, whose own button says the agent is at work.
    const busy = page.locator('.details button[aria-busy="true"]')
    await expect(busy).toHaveText(/Agent is thinking…/)
    await expect(busy).toHaveAttribute('aria-disabled', 'true')
    expect(await busy.evaluate(e => [e.disabled, getComputedStyle(e).opacity])).toEqual([false, '1'])
    expect((await line(busy)).name).toBe('btn-busy')
    await busy.click({ force: true })
    expect(sent).toBe(1)
  })
})
