import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import NSEC3 from '../../rr/nsec3.js'

const defaults = { class: 'IN', ttl: 3600, type: 'NSEC3' }

const validRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    'hash algorithm': 1,
    flags: 1,
    iterations: 12,
    salt: 'aabbccdd',
    'type bit maps': 'A RRSIG',
    'next hashed owner name': '2vptu5timamqttgl4luu9kg21e0aor3s',
    testB:
      'test.example.com.\t3600\tIN\tNSEC3\t1\t1\t12\taabbccdd\t2vptu5timamqttgl4luu9kg21e0aor3s\tA RRSIG\n',
    testT:
      ':test.example.com:50:\\001\\001\\000\\014\\004\\252\\273\\314\\335\\024\\027\\363\\337\\027\\262\\262\\255\\256\\366\\025%}\\344\\322\\002\\013\\200\\254l|\\000\\006@\\000\\000\\000\\000\\002:3600::\n',
    testW:
      '0474657374076578616d706c6503636f6d000032000100000e1000260101000c04aabbccdd1417f3df17b2b2adaef615257de4d2020b80ac6c7c0006400000000002',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    flags: 1,
    iterations: 12,
    salt: 'aabbccdd',
    'type bit maps': 'A',
    'next hashed owner name': '2vptu5timamqttgl4luu9kg21e0aor3s',
    msg: /'hash algorithm' is required/i,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    'hash algorithm': 1,
    iterations: 12,
    salt: 'aabbccdd',
    'type bit maps': 'A',
    'next hashed owner name': '2vptu5timamqttgl4luu9kg21e0aor3s',
    msg: /'flags' is required/i,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    'hash algorithm': 1,
    flags: 1,
    salt: 'aabbccdd',
    'type bit maps': 'A',
    'next hashed owner name': '2vptu5timamqttgl4luu9kg21e0aor3s',
    msg: /'iterations' is required/i,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    'hash algorithm': 1,
    flags: 1,
    iterations: 12,
    salt: 'aabbccdd',
    'type bit maps': 'A',
    msg: /'next hashed owner name' is required/i,
  },
]

describe('NSEC3 record', function () {
  base.valid(NSEC3, validRecords)
  base.invalid(NSEC3, invalidRecords, { ttl: 3600 })

  base.getDescription(NSEC3)
  base.getRFCs(NSEC3, validRecords[0])
  base.getFields(NSEC3, [
    'hash algorithm',
    'flags',
    'iterations',
    'salt',
    'next hashed owner name',
    'type bit maps',
  ])
  base.getCanonical(NSEC3)
  base.getTypeId(NSEC3, 50)
  base.getTags(NSEC3)

  base.toBind(NSEC3, validRecords)
  base.toWire(NSEC3, validRecords)
  base.toTinydns(NSEC3, validRecords)

  base.fromBind(NSEC3, validRecords)
  base.fromTinydns(NSEC3, validRecords)
  base.fromWire(NSEC3, validRecords)

  it('imports BIND output and encodes the wire as named-rrchecker does (RFC 5155 §3.2)', function () {
    const r = NSEC3.fromBind('h.example. 300 IN NSEC3 1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR')
    assert.equal(r.get('next hashed owner name'), '2t7b4g4vsa5smi47k61mv5bv1a22bojr')
    assert.equal(r.get('type bit maps'), '')
    assert.equal(
      Buffer.from(r.getWireRdata()).toString('hex'),
      '010000000014174eb2409fe28bcb4887a1836f957f0a8425e27b',
    )
    assert.deepEqual(NSEC3.fromWire(r.toWire()).toJSON(), r.toJSON())
  })

  it('lowercases salt and hash', function () {
    const r = NSEC3.fromBind(
      'h.example. 300 IN NSEC3 1 1 12 AABBCCDD 2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S A RRSIG',
    )
    assert.equal(r.get('salt'), 'aabbccdd')
    assert.equal(r.get('next hashed owner name'), '2vptu5timamqttgl4luu9kg21e0aor3s')
  })

  it('requires a 20-byte hash for SHA-1 (RFC 5155 §11)', function () {
    assert.throws(
      () => NSEC3.fromBind('h.example. 300 IN NSEC3 1 0 0 - ab A'),
      /SHA-1 'next hashed owner name' is 20 bytes, got 1/,
    )
  })

  it('rejects a hash that is not base32hex', function () {
    assert.throws(
      () => NSEC3.fromBind('h.example. 300 IN NSEC3 1 1 12 - 2vptu5timamqttgl4luu9kg21e0aor3w A'),
      /must be base32hex/,
    )
  })
})
