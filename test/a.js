
const assert = require('assert')

const base = require('./base')
const A = require('../rr/a.js')

const validRecords = [
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'A',
    address: '127.0.0.127',
    ttl    : 3600,
  },
]

const invalidRecords = [
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'A',
    address: 'hosts.not.valid.here',
    ttl    : 3600,
  },
]

describe('A record', function () {
  base.valid(A, validRecords)
  base.invalid(A, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new A(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, 'test.example.com\t3600\tIN\tA\t127.0.0.127\n')
    })

    it('converts to tinydns format', async function () {
      const r = new A(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      // console.dir(r)
      assert.strictEqual(r, '+test.example.com:127.0.0.127:3600::\n')
    })
  }
})
