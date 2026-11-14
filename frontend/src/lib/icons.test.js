// The rules of the icon system (lib/icons.js), checked on the sources:
// node --test "src/**/*.test.js"
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { ICONS, ICON_NAMES } from './icons.js'
import { pressable } from './pressable.js'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..')
const jsxFiles = dir => readdirSync(dir, { withFileTypes: true }).flatMap(e =>
  e.isDirectory() ? jsxFiles(join(dir, e.name)) : e.name.endsWith('.jsx') ? [join(dir, e.name)] : [])
const SOURCES = jsxFiles(SRC).map(path => ({ path: path.slice(SRC.length + 1), text: readFileSync(path, 'utf8') }))

// Everything a reader presses: <button>, <a>, and the <label> of a file input.
const controls = ({ path, text }) =>
  [...text.matchAll(/<(button|a|label)\b[\s\S]*?<\/\1>/g)].map(m => ({
    path, line: text.slice(0, m.index).split('\n').length, tag: m[1], code: m[0],
  }))
const CONTROLS = SOURCES.flatMap(controls)
const where = c => `${c.path}:${c.line}`

// Arrows, technical symbols, box and geometric shapes, dingbats, emoji: what
// the buttons used as icons before, each drawn by a different system font.
const GLYPH = /[←-⇿⌀-⏿■-⟿⤀-⯿\u{1F000}-\u{1FAFF}]|[⁰-₟]/u

test('the sources hold buttons to check', () => {
  assert.ok(CONTROLS.filter(c => c.tag === 'button').length >= 70)
})

test('an icon is a few open paths on the 16x16 grid', () => {
  assert.ok(ICON_NAMES.length > 0)
  for (const [name, paths] of Object.entries(ICONS)) {
    assert.ok(Array.isArray(paths) && paths.length > 0, name)
    for (const d of paths) {
      assert.match(d, /^M[\dMmLlHhVvAaZz .,-]+$/, `${name}: lines and arcs only`)
      const numbers = d.replace(/[Aa][^MmLlHhVvZz]*/g, '').match(/-?\d*\.?\d+/g).map(Number)
      assert.ok(numbers.every(n => n >= -16 && n <= 16), `${name}: inside the grid`)
    }
  }
})

test('every <Icon name> used in the sources exists', () => {
  const used = SOURCES.flatMap(({ path, text }) =>
    [...text.matchAll(/<Icon\b[^>]*?name=(?:"([^"]+)"|\{([^}]+)\})/g)].flatMap(m =>
      (m[1] ? [m[1]] : [...m[2].matchAll(/[?:]\s*'([^']+)'/g)].map(x => x[1])).map(name => ({ path, name }))))
  assert.ok(used.length > 30)
  for (const { path, name } of used) assert.ok(ICONS[name], `${path}: unknown icon "${name}"`)
  const unused = ICON_NAMES.filter(n => !used.some(u => u.name === n))
  assert.deepEqual(unused, [], 'an icon nothing uses')
})

test('no control is labelled with a glyph or an emoji', () => {
  const bad = CONTROLS.filter(c => GLYPH.test(c.code)).map(c => `${where(c)} ${c.code.match(GLYPH)[0]}`)
  assert.deepEqual(bad, [])
})

test('a button that holds only an icon has an aria-label', () => {
  const iconOnly = CONTROLS.filter(c => /<Icon\b[^>]*\bsolo\b/.test(c.code) && c.tag === 'button')
  assert.ok(iconOnly.length >= 15)
  const unnamed = iconOnly.filter(c => !/aria-label=/.test(c.code)).map(where)
  assert.deepEqual(unnamed, [])
})

test('a button that shows a state (class "active" or "on") says it to assistive technology', () => {
  const stateful = CONTROLS.filter(c => c.tag === 'button' && /\? ' (active|on)'/.test(c.code))
  assert.ok(stateful.length >= 10)
  const silent = stateful
    .filter(c => !/aria-(pressed|selected|expanded|current)=/.test(c.code)).map(where)
  assert.deepEqual(silent, [])
})

test('pressable() makes an element a keyboard button, and nothing of a plain one', () => {
  assert.deepEqual(pressable(undefined), {})
  let pressed = 0
  const props = pressable(() => { pressed++ })
  assert.equal(props.role, 'button')
  assert.equal(props.tabIndex, 0)
  const key = (k, target = 'self') => {
    let prevented = false
    props.onKeyDown({ key: k, target, currentTarget: 'self', preventDefault: () => { prevented = true } })
    return prevented
  }
  assert.equal(key('Enter'), true)
  assert.equal(key(' '), true)
  assert.equal(key('a'), false)
  assert.equal(key('Enter', 'a child'), false)   // a key typed in something inside it
  props.onClick()
  assert.equal(pressed, 3)
})
