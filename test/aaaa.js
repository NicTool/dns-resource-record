import assert from 'node:assert/strict'

import * as base from './base.js'
import AAAA from '../rr/aaaa.js'

const defaults = { class: 'IN', ttl: 3600, type: 'AAAA' }

const validRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    address: '2001:0db8:0020:000a:0000:0000:0000:0004',
    testB: 'test.example.com.\t3600\tIN\tAAAA\t2001:db8:20:a::4\n',
    testT:
      ':test.example.com:28:\\040\\001\\015\\270\\000\\040\\000\\012\\000\\000\\000\\000\\000\\000\\000\\004:3600::\n',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    address: '192.0.2.204',
    msg: /address must be IPv6/,
  },
]

describe('AAAA record', function () {
  base.valid(AAAA, validRecords)
  base.invalid(AAAA, invalidRecords)

  base.getDescription(AAAA)
  base.getRFCs(AAAA, validRecords[0])
  base.getFields(AAAA, ['address'])
  base.getTypeId(AAAA, 28)

  base.toBind(AAAA, validRecords)
  base.toTinydns(AAAA, validRecords)

  base.fromBind(AAAA, validRecords)
  base.fromTinydns(AAAA, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns AAAA (generic) record (${val.owner})`, async function () {
      const r = new AAAA({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'address', 'ttl']) {
        assert.deepEqual(
          r.get(f),
          val[f],
          `${f}: ${r.get(f)} !== ${val[f]}`,
        )
      }
    })
  }

  const tests = [
    { e: '2001:0db8:0020:000a:0000:0000:0000:0004', c: '2001:db8:20:a::4' },
    { e: '0000:0000:0000:0000:0000:0000:0000:0000', c: '::' },
    { e: '0000:0000:0000:0000:0000:0000:0000:0001', c: '::1' },
    { e: '2001:0db8:0000:0000:0000:0000:0002:0001', c: '2001:db8::2:1' },
    { e: '2001:0db8:0000:0001:0001:0001:0001:0001', c: '2001:db8:0:1:1:1:1:1' },
    {
      e: '2001:0DB8:0000:0000:0008:0800:200C:417A',
      c: '2001:DB8::8:800:200C:417A',
    },
  ]

  describe('compress', function () {
    const r = new AAAA(null)
    for (const t of tests) {
      it(`compresses IPv6 address (${t.e})`, function () {
        assert.equal(r.compress(t.e), t.c)
      })
    }
  })

  describe('expand', function () {
    const r = new AAAA(null)
    for (const t of tests) {
      it(`expands IPv6 address (${t.c})`, function () {
        assert.equal(r.expand(t.c), t.e)
      })
    }
  })
})
