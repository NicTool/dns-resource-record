
const assert = require('assert')

const base = require('./base')

const NS = require('../rr/ns')

const validRecords = [
  {
    class: 'IN',
    name : 'example.com',
    type : 'NS',
    dname: 'ns1.example.com.',
    ttl  : 3600,
    testR: 'example.com\t3600\tIN\tNS\tns1.example.com.\n',
    testT: '&example.com::ns1.example.com.:3600::\n',
  },
]

const invalidRecords = [
  {
    class: 'IN',
    name : 'example.com',
    type : 'NS',
    dname: '1.2.3.4',  // FQDN required
    ttl  : 3600,
  },
]

describe('NS record', function () {
  base.valid(NS, validRecords)
  base.invalid(NS, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new NS(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it('converts to tinydns format', async function () {
      const r = new NS(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testT)
    })

    it(`imports tinydns NS (&) record (${val.name})`, async function () {
      const r = new NS({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      const expected = JSON.parse(JSON.stringify(val))
      for (const f of [ 'name', 'dname', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), expected[f], `${f}: ${r[f]} !== ${expected[f]}`)
      }
    })
  }
})
