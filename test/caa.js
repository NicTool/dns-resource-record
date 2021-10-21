
const assert = require('assert')

const base = require('./base')

const CAA = require('../rr/caa')

const validRecords = [
  {
    class: 'IN',
    name : 'ns1.example.com',
    type : 'CAA',
    flags: 0,
    tags : 'issue',
    value: 'letsencrypt.org',
    ttl  : 3600,
    testR: `ns1.example.com\t3600\tIN\tCAA\t0\tissue\t"letsencrypt.org"\n`,
  },
  {
    class: 'IN',
    name : 'ns1.example.com',
    type : 'CAA',
    flags: 0,
    tags : 'issue',
    value: '"lets crypt.org"',
    ttl  : 3600,
    testR: `ns1.example.com\t3600\tIN\tCAA\t0\tissue\t"lets crypt.org"\n`,
  },
]

const invalidRecords = [
  {
    class: 'IN',
    name : 'example.com',
    type : 'CAA',
    flags: 1,
    tags : 'issue',
    value: 'lets encrypt.org', // spaces aren't allowed unless quoted
    ttl  : 3600,
  },
]

describe('CAA record', function () {
  base.valid(CAA, validRecords)
  base.invalid(CAA, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new CAA(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it.skip('converts to tinydns format', async function () {
      const r = new CAA(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, '\n')
    })
  }
})
