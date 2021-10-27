
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
    testB   : 'test.example.com\t3600\tIN\tMX\t0\tmail.example.com.\n',
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

  base.toBind(MX, validRecords)
  base.toTinydns(MX, validRecords)

  base.fromTinydns(MX, validRecords)

  base.getRFCs(MX, validRecords[0])

  for (const val of validRecords) {
    it.skip(`imports tinydns MX (@) record (${val.name})`, async function () {
      const r = new MX({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'exchange', 'weight', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
