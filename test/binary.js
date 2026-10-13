import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { bitmapToTypes, typeNameToId, typeIdToName, typesToBitmap } from '../lib/binary.js'

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

describe('bitmapToTypes (RFC 4034 §4.1.2)', function () {
  it('round trips a type list', function () {
    assert.equal(bitmapToTypes(typesToBitmap('A MX RRSIG NSEC TYPE1234')), 'A MX RRSIG NSEC TYPE1234')
  })

  for (const [bytes, msg] of [
    [[0, 2, 0x40], /truncated/],
    [[0], /inside a block header/],
    [[0, 0], /length 0 is not 1-32/],
    [[0, 33, ...Array(33).fill(1)], /length 33 is not 1-32/],
    [[0, 2, 0x40, 0], /ends in a zero octet/],
    [[1, 1, 0x40, 0, 1, 0x40], /window 0 is out of order/],
  ]) {
    it(`rejects ${JSON.stringify(bytes.slice(0, 6))}`, function () {
      assert.throws(() => bitmapToTypes(Uint8Array.from(bytes)), msg)
    })
  }
})
