
const assert = require('assert')

const base = require('./base')

const CNAME = require('../rr/cname')

const validRecords = [
  {
    class: 'IN',
    name : 'ns1.example.com',
    type : 'CNAME',
    cname: 'ns2.example.com.',
    ttl  : 3600,
    testR: 'ns1.example.com\t3600\tIN\tCNAME\tns2.example.com.\n',
    testT: 'Cns1.example.com:ns2.example.com.:3600::\n',
  },
]

const invalidRecords = [
  {
    class: 'IN',
    name : 'example.com',
    type : 'CNAME',
    cname: '1.2.3.4',  // FQDN required
    ttl  : 3600,
  },
]

describe('CNAME record', function () {
  base.valid(CNAME, validRecords)
  base.invalid(CNAME, invalidRecords)

  base.toBind(CNAME, validRecords)
  base.toTinydns(CNAME, validRecords)

  base.getRFCs(CNAME, validRecords[0])

  for (const val of validRecords) {

    it(`imports tinydns CNAME (C) record (${val.name})`, async function () {
      const r = new CNAME({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'cname', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
