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
  signature: 'ZHVtbXlzaWduYXR1cmU=',
  'signers name': 'example.com.',
}

const validRecords = [
  {
    ...defaults,
    'type covered': 1,
    testB:
      'example.com.\t3600\tIN\tRRSIG\t1\t5\t1\t3600\t1678886400\t1678886400\t12345\texample.com.\tZHVtbXlzaWduYXR1cmU=\n',
    testT:
      ':example.com:46:\\000\\001\\005\\001\\000\\000\\016\\020\\144\\021\\306\\000\\144\\021\\306\\000\\060\\071\\007example\\003com\\000dummysignature:3600::\n',
    testW:
      '076578616d706c6503636f6d00002e000100000e10002d0001050100000e106411c6006411c6003039076578616d706c6503636f6d0064756d6d797369676e6174757265',
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
  base.fromWire(RRSIG, validRecords)

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
      'example.com.\t3600\tIN\tRRSIG\tTYPE28\t5\t1\t3600\t1678886400\t1678886400\t12345\texample.com.\tc2ln\n'
    const r = RRSIG.fromBind(bindline)
    assert.equal(r.get('type covered'), 28)
  })

  // RFC 5155, 5702, 5933, 6605, 8080 — modern DNSSEC algorithms must be accepted
  for (const algo of [6, 7, 8, 10, 13, 14, 15, 16]) {
    it(`accepts DNSSEC algorithm ${algo}`, function () {
      const r = new RRSIG({ ...defaults, 'type covered': 1, algorithm: algo })
      assert.equal(r.get('algorithm'), algo)
    })
  }

  it('rejects an unassigned algorithm', function () {
    assert.throws(() => new RRSIG({ ...defaults, 'type covered': 1, algorithm: 99 }), /algorithm invalid/i)
  })

  // RFC 4034 §3.2: the signature is base64 in presentation form and raw bytes
  // on the wire.
  it('carries the decoded signature bytes on the wire', function () {
    const raw = Buffer.from(
      '25e937f8c4a0b1d2e3f405162738495a6b7c8d9eaf0011223344556677889900' +
        'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
      'hex',
    )
    const signature = raw.toString('base64')
    const r = new RRSIG({ ...defaults, 'type covered': 1, signature })

    const rdata = Buffer.from(r.getWireRdata())
    assert.deepEqual(rdata.subarray(rdata.length - raw.length), raw)
    assert.equal(rdata.length, 18 + 13 + raw.length)
  })

  it('round-trips a binary signature through tinydns and bind', function () {
    const signature = Buffer.from(
      'f0e1d2c3b4a5968778695a4b3c2d1e0fdeadbeefcafef00dba5eba11',
      'hex',
    ).toString('base64')
    const r = new RRSIG({ ...defaults, 'type covered': 1, signature })

    assert.equal(RRSIG.fromTinydns(r.toTinydns().trim()).get('signature'), signature)
    assert.equal(RRSIG.fromBind(r.toBind()).get('signature'), signature)
  })

  it('rejects a signature that is not base64', function () {
    assert.throws(
      () => new RRSIG({ ...defaults, 'type covered': 1, signature: 'not base64!' }),
      /signature must be a valid base64 string/i,
    )
  })
})
