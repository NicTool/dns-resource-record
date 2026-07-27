import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { typeNameToId, typeIdToName } from '../lib/binary.js'

describe('BINARY', function () {
  describe('typeNameToId', function () {
    const valid = [
      ['MX', 15],
      ['mx', 15],
      ['A', 1],
      ['TYPE123', 123],
      ['type123', 123],
      ['TYPE0', 0],
      ['TYPE65535', 65535],
      ['123', 123],
      [123, 123],
      [0, 0],
      [65535, 65535],
    ]
    for (const [input, expected] of valid) {
      it(`resolves ${JSON.stringify(input)} to ${expected}`, function () {
        assert.equal(typeNameToId(input), expected)
      })
    }

    it('resolves the NSAP_PTR input-only alias', function () {
      assert.equal(typeNameToId('NSAP_PTR'), 23)
      assert.equal(typeNameToId('NSAP-PTR'), 23)
    })

    const invalid = [
      'BOGUS',
      'TYPE70000',
      'TYPE65536',
      70000,
      -1,
      1.5,
      '',
      'TYPE-1',
      'TYPE1x',
      undefined,
      null,
      [15],
      { type: 15 },
      new String('MX'),
      Symbol('MX'),
    ]
    for (const input of invalid) {
      it(`throws on ${String(input)}`, function () {
        assert.throws(() => typeNameToId(input), /invalid DNS type/)
      })
    }
  })

  describe('typeIdToName', function () {
    it('resolves 15 to MX', function () {
      assert.equal(typeIdToName(15), 'MX')
    })

    it('resolves 1 to A', function () {
      assert.equal(typeIdToName(1), 'A')
    })

    it('resolves 23 to the IANA registered mnemonic NSAP-PTR', function () {
      assert.equal(typeIdToName(23), 'NSAP-PTR')
    })

    it('falls back to TYPE731 for unassigned ids (RFC 3597)', function () {
      assert.equal(typeIdToName(731), 'TYPE731')
    })

    const invalid = [-1, 65536, 1.5, '15', undefined, null]
    for (const input of invalid) {
      it(`throws on ${String(input)}`, function () {
        assert.throws(() => typeIdToName(input), /invalid DNS type id/)
      })
    }
  })
})
