
const assert = require('assert')

const base = require('./base')

const SPF = require('../rr/spf')

const validRecords = [
  {
    type : 'SPF',
    name : 'example.com',
    data : 'v=spf1 mx a include:mx.example.com -all',
    ttl  : 86400,
    testR: 'example.com\t86400\tIN\tSPF\t"v=spf1 mx a include:mx.example.com -all"\n',
    testT: ':example.com:99:v=spf1 mx a include\\072mx.example.com -all:86400::\n',
  },
]

const invalidRecords = [
]

describe('SPF record', function () {
  base.valid(SPF, validRecords)
  base.invalid(SPF, invalidRecords)

  base.toBind(SPF, validRecords)
  base.toTinydns(SPF, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns SPF (generic) record`, async function () {
      const r = new SPF({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'data', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})