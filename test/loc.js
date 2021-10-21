
const assert = require('assert')

const base = require('./base')

const LOC = require('../rr/loc')

const validRecords = [
  {
    class  : 'IN',
    name   : 'loc.home.example.com',
    type   : 'LOC',
    address: '47 43 47 N 122 21 35 W 132 100m 100m 2m',
    ttl    : 3600,
    testR  : `loc.home.example.com\t3600\tIN\tLOC\t47 43 47 N 122 21 35 W 132 100m 100m 2m\n`,
  },
]

const invalidRecords = [
  {
    class  : 'IN',
    name   : 'server.example.com',
    type   : 'LOC',
    address: '', // empty
    ttl    : 3600,
  },
]

describe('LOC record', function () {
  base.valid(LOC, validRecords)
  base.invalid(LOC, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new LOC(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it.skip('converts to tinydns format', async function () {
      const r = new LOC(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, '\n')
    })
  }
})
