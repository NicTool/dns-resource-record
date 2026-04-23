import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import RRSIG from '../../rr/rrsig.js'

const defaults = {
  class: 'IN',
  ttl: 3600,
  type: 'RRSIG',
  owner: 'example.com.',
  algorithm: 5,
  'key tag': 12345,
  labels: 1,
  'original ttl': 3600,
  'signature expiration': 1678886400,
  'signature inception': 1678886400,
  signature: 'dummysignature==',
  'signers name': 'example.com.',
}

const validRecords = [
  {
    ...defaults,
    'type covered': 1,
    testB:
      'example.com.\t3600\tIN\tRRSIG\t1\t5\t1\t3600\t1678886400\t1678886400\t12345\texample.com.\tdummysignature==\n',
    testT:
      ':example.com:46:\\000\\001\\005\\001\\000\\000\\016\\020\\144\\021\\306\\000\\144\\021\\306\\000\\060\\071\\007example\\003com\\000dummysignature==:3600::\n',
    testW:
      '076578616d706c6503636f6d00002e000100000e10002f0001050100000e106411c6006411c6003039076578616d706c6503636f6d0064756d6d797369676e61747572653d3d',
  },
]

const invalidRecords = [
  {
    ...defaults,
    msg: /'type covered' is required/i,
  },
  {
    ...defaults,
    'type covered': 'NOTATYPE',
    msg: /not a recognized type name/i,
  },
  {
    ...defaults,
    'type covered': 99999,
    msg: /must be a 16-bit integer/i,
  },
  {
    ...defaults,
    'type covered': -1,
    msg: /must be a 16-bit integer/i,
  },
  {
    ...defaults,
    'type covered': 1,
    algorithm: 99,
    msg: /algorithm invalid/i,
  },
]

describe('RRSIG record', function () {
  base.valid(RRSIG, validRecords)
  base.invalid(RRSIG, invalidRecords)

  base.getDescription(RRSIG)
  base.getRFCs(RRSIG, validRecords[0])
  base.getFields(RRSIG, [
    'type covered',
    'algorithm',
    'labels',
    'original ttl',
    'signature expiration',
    'signature inception',
    'key tag',
    'signers name',
    'signature',
  ])
  base.getCanonical(RRSIG)
  base.getTypeId(RRSIG, 46)
  base.getTags(RRSIG)

  base.toBind(RRSIG, validRecords)
  base.toWire(RRSIG, validRecords)
  base.toTinydns(RRSIG, validRecords)

  base.fromBind(RRSIG, validRecords)
  base.fromTinydns(RRSIG, validRecords)

  // test outside of roundtrip tests b/c mnemonic types are stored as ints
  it('resolves type name string "A" to numeric 1', function () {
    const r = new RRSIG({ ...defaults, 'type covered': 'A' })
    assert.equal(r.get('type covered'), 1)
  })

  it('resolves type name string "MX" to numeric 15', function () {
    const r = new RRSIG({ ...defaults, 'type covered': 'MX' })
    assert.equal(r.get('type covered'), 15)
  })

  it('resolves TYPEnn string "TYPE28" to numeric 28', function () {
    const r = new RRSIG({ ...defaults, 'type covered': 'TYPE28' })
    assert.equal(r.get('type covered'), 28)
  })

  it('fromBind resolves TYPEnn in type covered field', function () {
    const bindline =
      'example.com.\t3600\tIN\tRRSIG\tTYPE28\t5\t1\t3600\t1678886400\t1678886400\t12345\texample.com.\tsig==\n'
    const r = RRSIG.fromBind(bindline)
    assert.equal(r.get('type covered'), 28)
  })
})

  base.fromWire(RRSIG, validRecords)
