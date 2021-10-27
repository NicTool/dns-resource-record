
const assert = require('assert')

const base = require('./base')

const HINFO = require('../rr/hinfo')

const validRecords = [
  {
    class: 'IN',
    type : 'HINFO',
    name : 'server-under-my-desk.example.com',
    cpu  : 'PDP-11/73',
    os   : 'UNIX',
    ttl  : 86400,
    testB: 'server-under-my-desk.example.com\t86400\tIN\tHINFO\t"PDP-11/73"\t"UNIX"\n',
    // testT : ':server-under-my-desk:13: :86400::\n',
  },
]

const invalidRecords = [
  {
    name   : 'www.example.com',
    type   : 'HINFO',
    address: '',
    // ttl    : 3600,
  },
]

describe('HINFO record', function () {
  base.valid(HINFO, validRecords)
  base.invalid(HINFO, invalidRecords)

  base.toBind(HINFO, validRecords)
  // base.toTinydns(HINFO, validRecords)

  // base.fromTinydns(HINFO, validRecords)

  base.getRFCs(HINFO, validRecords[0])

  for (const val of validRecords) {
    it.skip(`imports tinydns HINFO (generic) record (${val.name})`, async function () {
      const r = new HINFO({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'address', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
