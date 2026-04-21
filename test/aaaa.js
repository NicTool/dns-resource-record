import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import AAAA from '../rr/aaaa.js'
import * as base from './base.js'

const defaults = { class: 'IN', ttl: 3600, type: 'AAAA' }

const validRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    address: '2001:0db8:0020:000a:0000:0000:0000:0004',
    testB: 'test.example.com.\t3600\tIN\tAAAA\t2001:db8:20:a::4\n',
    testT:
      ':test.example.com:28:\\040\\001\\015\\270\\000\\040\\000\\012\\000\\000\\000\\000\\000\\000\\000\\004:3600::\n',
    testW: '0474657374076578616d706c6503636f6d00001c000100000e10001020010db80020000a0000000000000004',
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    ttl: 4294967295,
    address: '2001:0db8:0020:000a:0000:0000:0000:0004',
    testB: 'test.example.com.\t4294967295\tIN\tAAAA\t2001:db8:20:a::4\n',
    testT:
      ':test.example.com:28:\\040\\001\\015\\270\\000\\040\\000\\012\\000\\000\\000\\000\\000\\000\\000\\004:4294967295::\n',
    testW: '0474657374076578616d706c6503636f6d00001c0001ffffffff001020010db80020000a0000000000000004',
  },
  {
    ...defaults,
    owner: 'a.',
    ttl: 86400,
    address: '0000:0000:0000:0000:0000:0000:0000:0001',
    testB: 'a.\t86400\tIN\tAAAA\t::1\n',
    testT: ':a:28:\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\001:86400::\n',
    testW: '016100001c000100015180001000000000000000000000000000000001',
  },
  {
    ...defaults,
    owner: '*.example.com.',
    address: '2001:0db8:0000:0000:0000:0000:0002:0001',
    testB: '*.example.com.\t3600\tIN\tAAAA\t2001:db8::2:1\n',
    testT:
      ':*.example.com:28:\\040\\001\\015\\270\\000\\000\\000\\000\\000\\000\\000\\000\\000\\002\\000\\001:3600::\n',
    testW: '012a076578616d706c6503636f6d00001c000100000e10001020010db8000000000000000000020001',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'AAAA',
    address: '2001:0db8:0000:0000:0000:0000:0000:0001',
    testB: 'nictool.tnpi.net.\t3600\tIN\tAAAA\t2001:db8::1\n',
    testT:
      ':nictool.tnpi.net:28:\\040\\001\\015\\270\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\001:3600::\n',
    testW: '076e6963746f6f6c04746e7069036e657400001c000100000e10001020010db8000000000000000000000001',
  },
  {
    owner: 'www.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'AAAA',
    address: '2001:0db8:0000:0000:0000:0000:0000:0002',
    testB: 'www.nictool.tnpi.net.\t3600\tIN\tAAAA\t2001:db8::2\n',
    testT:
      ':www.nictool.tnpi.net:28:\\040\\001\\015\\270\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\002:3600::\n',
    testW: '03777777076e6963746f6f6c04746e7069036e657400001c000100000e10001020010db8000000000000000000000002',
  },
]

const invalidRecords = [
  { ...defaults, owner: '', msg: /RFC/ },
  { ...defaults, owner: 'something*', msg: /fully/ },
  { ...defaults, owner: 'some*thing', msg: /fully/ },
  { ...defaults, owner: '*something', msg: /fully/ },
  { ...defaults, owner: 'something.*', msg: /fully/ },
  { ...defaults, address: '192.0.2.204', msg: /address must be IPv6/ },
  { ...defaults, address: '2001:db8::zzzz', msg: /address must be IPv6/ },
  { ...defaults, address: '', msg: /address is required/ },
  { ...defaults, address: undefined, msg: /address is required/ },
  { ...defaults, ttl: '', msg: /TTL must be numeric/ },
  { ...defaults, ttl: -299, msg: /TTL must be a 32-bit integer/ },
  { ...defaults, ttl: 4294967296, msg: /TTL must be a 32-bit integer/ },
]

for (let i = 0; i < invalidRecords.length; i++) {
  invalidRecords[i] = { ...validRecords[0], ...invalidRecords[i] }
}

describe('AAAA record', function () {
  base.valid(AAAA, validRecords)
  base.invalid(AAAA, invalidRecords)

  base.getDescription(AAAA)
  base.getRFCs(AAAA, validRecords[0])
  base.getRdataFields(AAAA, ['address'])
  base.getFields(AAAA, ['address'])
  base.getCanonical(AAAA)
  base.getTypeId(AAAA, 28)
  base.getTags(AAAA)

  base.toBind(AAAA, validRecords)
  base.toWire(AAAA, validRecords)
  base.toTinydns(AAAA, validRecords)

  base.fromBind(AAAA, validRecords)
  base.fromTinydns(AAAA, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns AAAA (generic) record (${val.owner})`, async function () {
      const r = new AAAA({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'address', 'ttl']) {
        assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
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
      e: '2001:0db8:0000:0000:0008:0800:200c:417a',
      c: '2001:db8::8:800:200c:417a',
    },
  ]

  describe('expand', function () {
    const r = new AAAA(null)
    for (const t of tests) {
      it(`expands IPv6 address (${t.c})`, function () {
        assert.equal(r.expand(t.c), t.e)
      })
    }
  })
})
