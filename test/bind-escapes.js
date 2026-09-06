// Copyright (c) 2026, The NicTool Contributors

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { TXT } from '../index.js'

test('TXT BIND round trips retain quotes, slashes and control characters', () => {
  for (const data of [
    'quote"value',
    'back\\slash',
    'a";still data',
    'line\nbreak',
    'tab\tvalue',
    'carriage\rreturn',
    'a\u0000b',
    'a\u001ab',
    '',
    ['a"b', 'c\\d'],
  ]) {
    const rr = new TXT({ owner: 'fixture.example.', ttl: 300, data })
    assert.deepEqual(TXT.fromBind(rr.toBind()).get('data'), data)
  }
})

test('quoted semicolons and escaped quotes do not begin comments', () => {
  assert.equal(TXT.fromBind('fixture.example. 300 IN TXT "a\\\";b" ; comment').get('data'), 'a";b')
})

test('quoted decimal escapes decode UTF-8 octets', () => {
  assert.equal(TXT.fromBind('fixture.example. 300 IN TXT "a\\032b\\195\\169"').get('data'), 'a bé')
})

test('malformed quoted strings and escapes fail', () => {
  for (const data of ['"unfinished', '"trailing\\', '"\\999"', '"\\255"']) {
    assert.throws(() => TXT.fromBind('fixture.example. 300 IN TXT ' + data))
  }
})
