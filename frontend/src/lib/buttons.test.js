// The button rules of styles.css and the busy state, checked on the sources:
// node --test "src/**/*.test.js". The rendered look is measured in
// e2e/button-style.spec.js.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { busyProps } from './pressable.js'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..')
const CSS = readFileSync(join(SRC, 'styles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')
const RULES = [...CSS.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map(m => ({ selector: m[1].trim().replace(/\s+/g, ' '), body: m[2] }))
const jsxFiles = dir => readdirSync(dir, { withFileTypes: true }).flatMap(e =>
  e.isDirectory() ? jsxFiles(join(dir, e.name)) : e.name.endsWith('.jsx') ? [join(dir, e.name)] : [])
const SOURCES = jsxFiles(SRC).map(path => ({ path: path.slice(SRC.length + 1), text: readFileSync(path, 'utf8') }))

test('hovered or pressed, nothing moves, grows or casts a shadow', () => {
  const states = RULES.filter(r => /:(hover|active)/.test(r.selector))
  assert.ok(states.length > 30)
  const moving = /(^|[;\s])(transform|translate|scale|box-shadow|filter|margin|padding|width|height|font-size|font-weight|border|border-width)\s*:/
  assert.deepEqual(states.filter(r => moving.test(r.body)).map(r => r.selector), [])
})

test('no transition on every property, and none over 110ms on a button', () => {
  assert.doesNotMatch(CSS, /transition:\s*all/)
  const buttons = RULES.filter(r => /(^|[\s,])(button|a\.btn-sm)|btn|-pill|switch-t|action-card|seg-option|panel-tab/.test(r.selector))
  const slow = buttons.flatMap(r => [...r.body.matchAll(/transition:([^;]+)/g)]
    .flatMap(m => [...m[1].matchAll(/([\d.]+)(ms|s)\b/g)])
    .filter(([, n, unit]) => Number(n) * (unit === 's' ? 1000 : 1) > 110)
    .map(([time]) => `${r.selector}: ${time}`))
  assert.deepEqual(slow, [])
})

test('the two animations of a button are switched off under reduced motion', () => {
  const reduced = [...CSS.matchAll(/@media \(prefers-reduced-motion: reduce\)\s*\{((?:[^{}]*\{[^{}]*\})*)\s*\}/g)].map(m => m[1]).join('\n')
  for (const selector of ['[aria-busy="true"]:where(button, label)::after', '.tick-draw path']) {
    assert.ok(RULES.some(r => r.selector.includes(selector) && /animation:\s*btn-/.test(r.body)), `${selector} is animated`)
    assert.match(reduced, new RegExp(selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '[^{]*\\{[^}]*animation:\\s*none'))
  }
})

test('the classes of the old look are gone from the sources', () => {
  const old = /className=[^>]*[\s\"'`](secondary|share-btn|auth-btn danger|icon-btn (primary|warning))\b/
  assert.deepEqual(SOURCES.filter(s => old.test(s.text)).map(s => s.path), [])
})

test('a busy button is announced, ignores a second press, and is not disabled', () => {
  const press = () => {}
  assert.deepEqual(busyProps(false, press), { onClick: press })
  assert.deepEqual(busyProps(true, press), { 'aria-busy': true, 'aria-disabled': true })
  // Every button that takes busyProps shows its two labels through <BusyLabel>.
  const users = SOURCES.filter(s => /busyProps\(/.test(s.text))
  assert.ok(users.length >= 6)
  for (const { path, text } of users) {
    const buttons = [...text.matchAll(/<button\b[\s\S]*?<\/button>/g)].map(m => m[0]).filter(b => /busyProps\(/.test(b))
    assert.ok(buttons.length > 0, path)
    for (const b of buttons) assert.match(b, /<BusyLabel\b/, `${path}: a busy button without <BusyLabel>`)
  }
})
