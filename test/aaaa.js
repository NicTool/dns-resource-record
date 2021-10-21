
const assert = require('assert')

const base = require('./base')
const AAAA = require('../rr/aaaa.js')

const validRecords = [
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'AAAA',
    address: '2605:7900:20:a::4',
    ttl    : 3600,
    testR  : 'test.example.com\t3600\tIN\tAAAA\t2605:7900:20:a::4\n',
  },
]

const invalidRecords = [
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'AAAA',
    address: '207.206.205.204',
    ttl    : 3600,
  },
]

describe('AAAA record', function () {
  base.valid(AAAA, validRecords)
  base.invalid(AAAA, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new AAAA(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it('converts to tinydns format', async function () {
      const r = new AAAA(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      // console.dir(r)
      assert.strictEqual(r, ':test.example.com:28:\\046\\005\\171\\000\\000\\040\\000\\012\\000\\000\\000\\000\\000\\000\\000\\004:3600::\n')
    })
  }
})