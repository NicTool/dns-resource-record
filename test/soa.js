
const assert = require('assert')

const base = require('./base')

const SOA = require('../rr/soa')

const validRecords = [
  {
    class  : 'IN',
    name   : 'example.com',
    type   : 'SOA',
    mname  : 'ns1.example.com.',
    rname  : 'matt.example.com.',
    serial : 1,
    refresh: 7200,
    retry  : 3600,
    expire : 1209600,
    minimum: 3600,
    ttl    : 3600,
  },
]

const invalidRecords = [
  {
    class  : 'IN',
    name   : 'example.com',
    type   : 'SOA',
    mname  : 'ns1.example.com.',
    rname  : 'matt.example.com.',
    serial : 4294967296,
    refresh: 7200,
    retry  : 3600,
    expire : 1209600,
    ttl    : 3600,
  },
]

describe('SOA record', function () {
  base.valid(SOA, validRecords)
  base.invalid(SOA, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new SOA(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, `$TTL    3600
$ORIGIN example.com.
example.com.   IN  SOA ns1.example.com.    matt.example.com. (
          1
          7200
          3600
          1209600
          3600
          )\n\n`)
    })

    it('converts to tinydns format', async function () {
      const r = new SOA(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, 'Zexample.com:ns1.example.com.:matt.example.com.:1:7200:3600:1209600:3600:3600::\n')
    })
  }
})