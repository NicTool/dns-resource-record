
const assert = require('assert')

const base = require('./base')

const DNAME = require('../rr/dname')

const validRecords = [
  {
    class : 'IN',
    name  : '_tcp.example.com',
    type  : 'DNAME',
    target: '_tcp.example.net.',
    ttl   : 86400,
  },
]

const invalidRecords = [
  {
    name  : 'spf.example.com',
    type  : 'DNAME',
    target: '1.2.3.4',  // FQDN required
    ttl   : 3600,
  },
]

describe('DNAME record', function () {
  base.valid(DNAME, validRecords)
  base.invalid(DNAME, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new DNAME(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, '_tcp.example.com\t86400\tIN\tDNAME\t_tcp.example.net.\n')
    })

    it.skip('converts to tinydns format', async function () {
      const r = new DNAME(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, '\n')
    })
  }
})
