
const assert = require('assert')

const base = require('./base')

const CNAME = require('../rr/cname')

const validRecords = [
  {
    class  : 'IN',
    name   : 'ns1.example.com',
    type   : 'CNAME',
    address: 'ns2.example.com.',
    ttl    : 3600,
    testR  : 'ns1.example.com\t3600\tIN\tCNAME\tns2.example.com.\n',
  },
]

const invalidRecords = [
  {
    class  : 'IN',
    name   : 'example.com',
    type   : 'CNAME',
    address: '1.2.3.4',  // FQDN required
    ttl    : 3600,
  },
]

describe('CNAME record', function () {
  base.valid(CNAME, validRecords)
  base.invalid(CNAME, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new CNAME(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it('converts to tinydns format', async function () {
      const r = new CNAME(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, 'Cns1.example.com:ns2.example.com.:3600::\n')
    })
  }
})
