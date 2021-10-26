
const assert = require('assert')

const base = require('./base')

const PTR = require('../rr/ptr')

const validRecords = [
  {
    class: 'IN',
    name : '2.1.0.10.in-addr.arpa',
    type : 'PTR',
    dname: 'dhcp.example.com.',
    ttl  : 86400,
    testR: '2.1.0.10.in-addr.arpa\t86400\tIN\tPTR\tdhcp.example.com.\n',
    testT: '^2.1.0.10.in-addr.arpa:dhcp.example.com.:86400::\n',
  },
]

const invalidRecords = [
  {
    class: 'IN',
    name : 'example.com',
    type : 'PTR',
    dname: '1.2.3.4',  // FQDN required
    ttl  : 3600,
  },
]

describe('PTR record', function () {
  base.valid(PTR, validRecords)
  base.invalid(PTR, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new PTR(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it('converts to tinydns format', async function () {
      const r = new PTR(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testT)
    })

    it(`imports tinydns PTR (^) record (${val.name})`, async function () {
      const r = new PTR({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      const expected = JSON.parse(JSON.stringify(val))
      for (const f of [ 'name', 'dname', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), expected[f], `${f}: ${r[f]} !== ${expected[f]}`)
      }
    })
  }
})
