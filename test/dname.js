
const assert = require('assert')

const base = require('./base')

const DNAME = require('../rr/dname')

const validRecords = [
  {
    class : 'IN',
    name  : '_tcp.example.com',
    type  : 'DNAME',
    target: '_tcp.example.net.',
    ttl   : 86400,
    testB : '_tcp.example.com\t86400\tIN\tDNAME\t_tcp.example.net.\n',
    testT : ':_tcp.example.com:39:\\004\\137tcp\\007example\\003net\\000:86400::\n',
  },
]

const invalidRecords = [
  {
    name  : 'spf.example.com',
    type  : 'DNAME',
    target: '1.2.3.4',  // FQDN required
    ttl   : 3600,
  },
]

describe('DNAME record', function () {
  base.valid(DNAME, validRecords)
  base.invalid(DNAME, invalidRecords)

  base.getRFCs(DNAME, validRecords[0])
  base.getFields(DNAME, [ 'target' ])

  base.toBind(DNAME, validRecords)
  base.toTinydns(DNAME, validRecords)

  base.fromBind(DNAME, validRecords)
  base.fromTinydns(DNAME, validRecords)

  for (const val of validRecords) {
    it.skip(`imports tinydns DNAME (generic) record (${val.name})`, async function () {
      const r = new DNAME({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'target', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
