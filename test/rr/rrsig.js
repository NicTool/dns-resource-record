import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import RRSIG from '../../rr/rrsig.js'

const defaults = {
  ttl: 3600,
  owner: 'example.com.',
  algorithm: 5,
  'key tag': 12345,
  labels: 2,
  'original ttl': 3600,
  'signature expiration': 1678886400,
  'signature inception': 1678886400,
  signature: 'ZHVtbXlzaWduYXR1cmU=',
  'signers name': 'example.com.',
}

const valid = [
  {
    ...defaults,
    'type covered': 1,
    testB:
      'example.com.\t3600\tIN\tRRSIG\tA\t5\t2\t3600\t1678886400\t1678886400\t12345\texample.com.\tZHVtbXlzaWduYXR1cmU=\n',
    testT:
      ':example.com:46:\\000\\001\\005\\002\\000\\000\\016\\020d\\021\\306\\000d\\021\\306\\00009\\007example\\003com\\000dummysignature:3600::\n',
    testW:
      '076578616d706c6503636f6d00002e000100000e10002d0001050200000e106411c6006411c6003039076578616d706c6503636f6d0064756d6d797369676e6174757265',
  },
]

const invalid = [
  {
    ...defaults,
    msg: /'type covered' is required/i,
  },
  {
    ...defaults,
    'type covered': 'NOTATYPE',
    msg: /not a type name, TYPEnnn, or 0-65535/,
  },
  {
    ...defaults,
    'type covered': 99999,
    msg: /not a type name, TYPEnnn, or 0-65535/,
  },
  {
    ...defaults,
    'type covered': -1,
    msg: /not a type name, TYPEnnn, or 0-65535/,
  },
  { ...defaults, 'type covered': 1, algorithm: 99, msg: /algorithm invalid/i },
  {
    ...defaults,
    'type covered': 1,
    signature: 'not base64!',
    msg: /signature must be a valid base64 string/i,
  },
  // RFC 4034 §3.1.3, §3.1.7
  { ...defaults, 'type covered': 1, labels: 3, msg: /labels \(3\) exceeds the owner's 2/ },
  { ...defaults, 'type covered': 1, labels: 1, msg: /signers name has 2 labels/ },
  {
    ...defaults,
    'type covered': 1,
    owner: 'host.example.com.',
    'signers name': 'other.test.',
    msg: /not the owner or an ancestor/,
  },
]

describe('RRSIG record', function () {
  base.suite(RRSIG, {
    typeId: 46,
    fields: [
      'type covered',
      'algorithm',
      'labels',
      'original ttl',
      'signature expiration',
      'signature inception',
      'key tag',
      'signers name',
      'signature',
    ],
    valid,
    invalid,
  })

  const rrsig = (opts) => new RRSIG({ ...defaults, 'type covered': 1, ...opts })

  it('stores times, types and names in canonical form', function () {
    for (const [opts, field, expected] of [
      [{ 'signature expiration': 19691231235959 }, 'signature expiration', 2 ** 32 - 1], // RFC 4034 §3.2
      [{ 'type covered': 'A' }, 'type covered', 1],
      [{ 'type covered': 'MX' }, 'type covered', 15],
      [{ 'type covered': 'TYPE28' }, 'type covered', 28],
      [{ owner: '*.example.com.', labels: 2 }, 'labels', 2],
      [{ owner: 'host.Example.com.', 'signers name': 'example.COM.' }, 'signers name', 'example.com.'],
      ...[6, 7, 8, 10, 13, 14, 15, 16].map((algorithm) => [{ algorithm }, 'algorithm', algorithm]),
    ]) {
      assert.equal(rrsig(opts).get(field), expected, JSON.stringify(opts))
    }
  })

  it('imports type mnemonics and YYYYMMDDHHmmSS times as dnssec-signzone writes them', function () {
    const r = RRSIG.fromBind(
      'r.example. 3600 IN RRSIG TYPE28 5 2 3600 20230315132000 20230315132000 12345 example. AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8no',
    )
    assert.equal(r.get('type covered'), 28)
    assert.equal(r.get('signature expiration'), 1678886400)
    assert.equal(r.get('signature inception'), 1678886400)
  })

  it('revalidates owner, labels and signer together, keeping values a setter rejects', function () {
    const r = rrsig()
    const before = r.toJSON()
    assert.throws(() => r.setLabels(3), /exceeds the owner's/)
    assert.throws(() => r.setLabels(1), /signers name has 2 labels, more than labels \(1\)/)
    assert.throws(() => r.setSignersName('other.test.'), /not the owner or an ancestor/)
    assert.throws(() => r.setOwner('other.test.'), /not the owner or an ancestor/)
    assert.deepEqual(r.toJSON(), before)
    r.setOwner('www.example.com.')
    assert.equal(r.get('owner'), 'www.example.com.')
  })

  // RFC 4034 §3.2: base64 in presentation form, raw bytes on the wire
  it('carries a binary signature through wire, tinydns and BIND', function () {
    const raw = Buffer.from('f0e1d2c3b4a5968778695a4b3c2d1e0fdeadbeefcafef00dba5eba11', 'hex')
    const r = rrsig({ signature: raw.toString('base64') })
    const rdata = Buffer.from(r.getWireRdata())
    assert.deepEqual(rdata.subarray(18 + 13), raw)
    assert.equal(RRSIG.fromTinydns(r.toTinydns()).get('signature'), r.get('signature'))
    assert.equal(RRSIG.fromBind(r.toBind()).get('signature'), r.get('signature'))
  })
})
