import test from 'node:test'
import assert from 'node:assert/strict'
import { nextInvSearch } from './invUrl.js'

test('deep link survives the mount-time sync (activeInv null, not hydrated)', () => {
  assert.equal(nextInvSearch('?inv=32bebc43129c', null, false), null)
})

test('once hydrated, clearing the active investigation drops the param', () => {
  assert.equal(nextInvSearch('?inv=abc', null, true), '')
  assert.equal(nextInvSearch('?inv=abc&vertical=osint', null, true), '?vertical=osint')
})

test('opening an investigation writes it, other params kept', () => {
  assert.equal(nextInvSearch('', 'abc', true), '?inv=abc')
  assert.equal(nextInvSearch('?vertical=dd', 'abc', true), '?vertical=dd&inv=abc')
  assert.equal(nextInvSearch('?inv=old', 'new', true), '?inv=new')
})

test('no change when URL already matches', () => {
  assert.equal(nextInvSearch('?inv=abc', 'abc', true), null)
  assert.equal(nextInvSearch('', null, true), null)
})
