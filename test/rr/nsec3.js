import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import NSEC3 from '../../rr/nsec3.js'

const valid = [
  {
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

const invalid = [
  ...['hash algorithm', 'flags', 'iterations', 'next hashed owner name'].map((f) => ({
    ...valid[0],
    [f]: undefined,
    msg: new RegExp(`'${f}' is required`, 'i'),
  })),
  // RFC 5155 §11
  {
    bindline: 'h.example. 300 IN NSEC3 1 0 0 - a8 A',
    msg: /SHA-1 'next hashed owner name' is 20 bytes, got 1/,
  },
  // RFC 5155 §3.2
  { bindline: `h.example. 300 IN NSEC3 2 0 0 - ${'a'.repeat(416)} A`, msg: /must be <=255 bytes, got 260/ },
  ...['2vptu5timamqttgl4luu9kg21e0aor3w', 'a', 'abc', 'ab'].map((hash) => ({
    bindline: `h.example. 300 IN NSEC3 2 1 12 - ${hash} A`,
    msg: /must be unpadded base32hex/,
  })),
]

describe('NSEC3 record', function () {
  base.suite(NSEC3, {
    typeId: 50,
    fields: ['hash algorithm', 'flags', 'iterations', 'salt', 'next hashed owner name', 'type bit maps'],
    valid,
    invalid,
  })

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

  it('rejects wire rdata whose salt or hash length overruns it', function () {
    const decode = (hex) =>
      new NSEC3(null).fromWire({ owner: 'h.example.', cls: 'IN', ttl: 60, rdata: Buffer.from(hex, 'hex') })
    assert.throws(() => decode('020000000002ab'), /hash length does not fit/)
    assert.throws(() => decode('0200000000'), /truncated before the hash/)
  })
})
