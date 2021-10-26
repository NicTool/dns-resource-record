
const assert = require('assert')

const base = require('./base')

const MX = require('../rr/mx')

const validRecords = [
  {
    class   : 'IN',
    name    : 'test.example.com',
    type    : 'MX',
    exchange: 'mail.example.com.',
    weight  : 0,
    ttl     : 3600,
    testR   : 'test.example.com\t3600\tIN\tMX\t0\tmail.example.com.\n',
    testT   : '@test.example.com::mail.example.com.:0:3600::\n',
  },
]

const invalidRecords = [
  {
    class   : 'IN',
    name    : 'test.example.com',
    type    : 'MX',
    exchange: 'not-full-qualified.example.com',
    ttl     : 3600,
  },
  {
    class   : 'IN',
    name    : 'test.example.com',
    type    : 'MX',
    exchange: '192.168.0.1',
    ttl     : 3600,
  },
]

describe('MX record', function () {
  base.valid(MX, validRecords)
  base.invalid(MX, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new MX(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it('converts to tinydns format', async function () {
      const r = new MX(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testT)
    })

    it(`imports tinydns MX (@) record (${val.name})`, async function () {
      const r = new MX({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      const expected = JSON.parse(JSON.stringify(val))
      for (const f of [ 'name', 'exchange', 'weight', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), expected[f], `${f}: ${r[f]} !== ${expected[f]}`)
      }
    })
  }
})
