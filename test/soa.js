
import assert from 'assert'

import * as base from './base.js'

import SOA from '../rr/soa.js'

const defaults = { class: 'IN', ttl: 3600, type: 'SOA' }

const validRecords = [
  {
    ...defaults,
    owner  : 'example.com.',
    mname  : 'ns1.example.com.',
    rname  : 'matt.example.com.',
    serial : 1,
    refresh: 7200,
    retry  : 3600,
    expire : 1209600,
    minimum: 3600,
    testB  : `example.com.\t3600\tIN\tSOA\tns1.example.com.\tmatt.example.com.\t1\t7200\t3600\t1209600\t3600\n`,
    testT  : 'Zexample.com:ns1.example.com:matt.example.com:1:7200:3600:1209600:3600:3600::\n',
  },
  {
    ...defaults,
    owner  : '2.example.com.',
    mname  : 'ns2.example.com.',
    rname  : 'matt.example.com.',
    serial : 1,
    refresh: 7200,
    retry  : 3600,
    expire : 1209600,
    minimum: 3600,
    testB  : `2.example.com.\t3600\tIN\tSOA\tns2.example.com.\tmatt.example.com.\t1\t7200\t3600\t1209600\t3600\n`,
    testT  : 'Z2.example.com:ns2.example.com:matt.example.com:1:7200:3600:1209600:3600:3600::\n',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner  : 'example.com.',
    mname  : 'ns1.example.com.',
    rname  : 'matt.example.com.',
    serial : 4294967296,
    refresh: 7200,
    retry  : 3600,
    expire : 1209600,
    msg    : /serial must be a 32-bit integer/,
  },
]

describe('SOA record', function () {
  base.valid(SOA, validRecords)
  base.invalid(SOA, invalidRecords)

  base.getDescription(SOA)
  base.getRFCs(SOA, validRecords[0])
  base.getFields(SOA, [ 'mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum' ])
  base.getTypeId(SOA, 6)

  base.toBind(SOA, validRecords)
  base.toTinydns(SOA, validRecords)

  base.fromBind(SOA, validRecords)
  base.fromTinydns(SOA, validRecords)

  for (const val of validRecords) {
    it.skip(`imports tinydns SOA (Z) record (${val.owner})`, async function () {
      const r = new SOA({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'owner', 'mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})