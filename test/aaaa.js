
const assert = require('assert')

const base = require('./base')
const AAAA = require('../rr/aaaa.js')

const validRecords = [
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'AAAA',
    address: '2001:db8:20:a::4',
    ttl    : 3600,
    testB  : 'test.example.com\t3600\tIN\tAAAA\t2001:db8:20:a::4\n',
    testT  : ':test.example.com:28:\\040\\001\\015\\270\\000\\040\\000\\012\\000\\000\\000\\000\\000\\000\\000\\004:3600::\n',
  },
]

const invalidRecords = [
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'AAAA',
    address: '192.0.2.204',
    ttl    : 3600,
  },
]

describe('AAAA record', function () {
  base.valid(AAAA, validRecords)
  base.invalid(AAAA, invalidRecords)

  base.getDescription(AAAA)
  base.getRFCs(AAAA, validRecords[0])
  base.getFields(AAAA, [ 'address' ])
  base.getTypeId(AAAA, 28)

  base.toBind(AAAA, validRecords)
  base.toTinydns(AAAA, validRecords)

  base.fromBind(AAAA, validRecords)
  base.fromTinydns(AAAA, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns AAAA (generic) record (${val.name})`, async function () {
      const r = new AAAA({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'address', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})