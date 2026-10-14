import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import DS from '../../rr/ds.js'

const defaults = { 'key tag': 60485, algorithm: 5, 'digest type': 1 }

const valid = [
  {
    ...defaults,
    owner: 'dskey.example.com.',
    digest: '2BB183AF5F22588179A53B0A98631FAD1A292118',
    testB: 'dskey.example.com.\t3600\tIN\tDS\t60485\t5\t1\t2BB183AF5F22588179A53B0A98631FAD1A292118\n',
    testT:
      ':dskey.example.com:43:\\354E\\005\\001+\\261\\203\\257_"X\\201y\\245;\\012\\230c\\037\\255\\032)!\\030:3600::\n',
    testW:
      '0564736b6579076578616d706c6503636f6d00002b000100000e100018ec4505012bb183af5f22588179a53b0a98631fad1a292118',
  },
]

const invalid = [
  {
    ...defaults,
    owner: 'test.example.com.',
    algorithm: 99,
    msg: /algorithm/,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    'key tag': 65536,
    msg: /must be a 16-bit integer/,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    digest: '00',
    'digest type': 3,
    msg: /digest type invalid/,
  },
]

describe('DS record', function () {
  base.suite(DS, {
    typeId: 43,
    fields: ['key tag', 'algorithm', 'digest type', 'digest'],
    valid,
    invalid,
  })

  it('accepts SHA-384 digests (RFC 6605) and modern DNSSEC algorithms', function () {
    const ds = (opts) => new DS({ ...defaults, ttl: 3600, owner: 'dskey.example.com.', ...opts })
    const sha384 =
      '72D7B62976CE06438E9C0BF319013CF801F09ECC84B8D7E9495F27E305C6A9B0563A9B5F4D288405C3008A946DF983D6'
    assert.equal(ds({ 'digest type': 4, digest: sha384 }).get('digest type'), 4)
    for (const algorithm of [6, 7, 8, 10, 13, 14, 15, 16])
      assert.equal(
        ds({ algorithm, digest: '2BB183AF5F22588179A53B0A98631FAD1A292118' }).get('algorithm'),
        algorithm,
      )
  })

  it('revalidates the digest when the digest type changes', function () {
    const r = new DS(new DS(null).getCanonical())
    assert.throws(() => r.setDigestType(2), /digest must be 32 bytes/)
    assert.equal(r.get('digest type'), 1)
  })
})
