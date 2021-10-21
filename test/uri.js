
const assert = require('assert')

const base = require('./base')

const URI = require('../rr/uri')

const validRecords = [
  {
    class   : 'IN',
    name    : 'www.example.com',
    type    : 'URI',
    target  : 'www2.example.com.',
    priority: 1,
    weight  : 0,
    ttl     : 3600,
    testR   : 'www.example.com\t3600\tIN\tURI\t1\t0\twww2.example.com.\n',
  },
]

const invalidRecords = [

]

describe('URI record', function () {
  base.valid(URI, validRecords)
  base.invalid(URI, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new URI(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it.skip('converts to tinydns format', async function () {
      const r = new URI(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, '\n')
    })
  }
})
