
const assert = require('assert')

const base = require('./base')

const SPF = require('../rr/spf')

const validRecords = [
  {
    name : 'example.com',
    type : 'SPF',
    data : 'v=spf1 mx a include:mx.example.com -all',
    ttl  : 86400,
    testR: 'example.com\t86400\tIN\tSPF\t"v=spf1 mx a include:mx.example.com -all"\n',
    testT: 'example.com:99:v=spf1 mx a include\\072mx.example.com -all:86400::\n',
  },
]

const invalidRecords = [
]

describe('SPF record', function () {
  base.valid(SPF, validRecords)
  base.invalid(SPF, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new SPF(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it('converts to tinydns format', async function () {
      const r = new SPF(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testT)
    })
  }
})