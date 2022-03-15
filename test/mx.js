
const assert = require('assert')

const base = require('./base')

const MX = require('../rr/mx')

const validRecords = [
  {
    name      : 'test.example.com',
    class     : 'IN',
    type      : 'MX',
    ttl       : 3600,
    preference: 0,
    exchange  : 'mail.example.com.',
    testB     : 'test.example.com\t3600\tIN\tMX\t0\tmail.example.com.\n',
    testT     : '@test.example.com::mail.example.com.:0:3600::\n',
  },
]

const invalidRecords = [
  {
    name    : 'test.example.com',
    exchange: 'not-full-qualified.example.com',
  },
  {
    name    : 'test.example.com',
    exchange: '192.0.2.1',
  },
  {
    name    : 'test.example.com',
    exchange: '-blah',
  },
]

const defaults = { ttl: 3600, preference: 0 }

describe('MX record', function () {
  base.valid(MX, validRecords)
  base.invalid(MX, invalidRecords, defaults)

  base.getDescription(MX)
  base.getRFCs(MX, validRecords[0])
  base.getFields(MX, [ 'preference', 'exchange' ])
  base.getTypeId(MX, 15)

  base.toBind(MX, validRecords)
  base.toTinydns(MX, validRecords)

  base.fromBind(MX, validRecords)
  base.fromTinydns(MX, validRecords)

  for (const val of validRecords) {
    it.skip(`imports tinydns MX (@) record (${val.name})`, async function () {
      const r = new MX({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'exchange', 'preference', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
