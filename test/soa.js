
const assert = require('assert')

const base = require('./base')

const SOA = require('../rr/soa')

const validRecords = [
  {
    class  : 'IN',
    owner  : 'example.com.',
    type   : 'SOA',
    mname  : 'ns1.example.com.',
    rname  : 'matt.example.com.',
    serial : 1,
    refresh: 7200,
    retry  : 3600,
    expire : 1209600,
    minimum: 3600,
    ttl    : 3600,
    testB  : `$TTL\t3600
$ORIGIN\texample.com.
example.com.\tIN\tSOA\tns1.example.com.\tmatt.example.com. (
\t\t1
\t\t7200
\t\t3600
\t\t1209600
\t\t3600
\t\t)\n\n`,
    testT: 'Zexample.com:ns1.example.com:matt.example.com:1:7200:3600:1209600:3600:3600::\n',
  },
]

const invalidRecords = [
  {
    owner  : 'example.com',
    ttl    : 3600,
    class  : 'IN',
    type   : 'SOA',
    mname  : 'ns1.example.com.',
    rname  : 'matt.example.com.',
    serial : 4294967296,
    refresh: 7200,
    retry  : 3600,
    expire : 1209600,
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