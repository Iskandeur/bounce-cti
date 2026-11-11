import { test, expect, expectGraphDrawn, historyItem, openFromHistory } from './harness.js'
import { INV_DOMAIN, INV_IP } from './fixtures/data.js'

const urlOf = inv => new RegExp(`/\\?inv=${inv}$`)

test('?inv=<id> opens that investigation and stays in the URL', async ({ page }) => {
  await page.goto(`/?inv=${INV_IP}`)
  await expectGraphDrawn(page, INV_IP)
  await expect(historyItem(page, '192.0.2.10')).toHaveClass(/active/)
  await expect(page).toHaveURL(urlOf(INV_IP))
})

test('the URL follows the open investigation, and a reload comes back to it', async ({ page }) => {
  await page.goto('/')
  await openFromHistory(page, 'example.com')
  await expectGraphDrawn(page, INV_DOMAIN)
  await expect(page).toHaveURL(urlOf(INV_DOMAIN))

  await page.reload()
  await expectGraphDrawn(page, INV_DOMAIN)
  await expect(historyItem(page, 'example.com')).toHaveClass(/active/)
  await expect(page).toHaveURL(urlOf(INV_DOMAIN))
})
