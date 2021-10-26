
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
    testT  : ':test.example.com:28:\\046\\005\\171\\000\\000\\040\\000\\012\\000\\000\\000\\000\\000\\000\\000\\004:3600::\n',
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

  base.toBind(AAAA, validRecords)
  base.toTinydns(AAAA, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns AAAA (6) record (${val.name})`, async function () {
      const r = new AAAA({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'address', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})