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
      ['NSAP_PTR', 23], // input-only alias
      ['NSAP-PTR', 23],
    ]
    for (const [input, expected] of valid) {
      it(`resolves ${JSON.stringify(input)} to ${expected}`, function () {
        assert.equal(typeNameToId(input), expected)
      })
    }

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

  it('typeIdToName', function () {
    // 23 is IANA's NSAP-PTR; unassigned ids fall back to TYPEnnn (RFC 3597)
    for (const [id, name] of [
      [15, 'MX'],
      [1, 'A'],
      [23, 'NSAP-PTR'],
      [731, 'TYPE731'],
    ]) {
      assert.equal(typeIdToName(id), name)
    }
    for (const input of [-1, 65536, 1.5, '15', undefined, null])
      assert.throws(() => typeIdToName(input), /invalid DNS type id/, String(input))
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
