
const assert = require('assert')

const base = require('./base')

const DNAME = require('../rr/dname')

const validRecords = [
  {
    owner : '_tcp.example.com.',
    ttl   : 86400,
    class : 'IN',
    type  : 'DNAME',
    target: '_tcp.example.net.',
    testB : '_tcp.example.com.\t86400\tIN\tDNAME\t_tcp.example.net.\n',
    testT : ':_tcp.example.com:39:\\004\\137tcp\\007example\\003net\\000:86400::\n',
  },
]

const invalidRecords = [
  {
    owner : 'spf.example.com',
    ttl   : 3600,
    type  : 'DNAME',
    target: '1.2.3.4',  // FQDN required
  },
]

describe('DNAME record', function () {
  base.valid(DNAME, validRecords)
  base.invalid(DNAME, invalidRecords)

  base.getDescription(DNAME)
  base.getRFCs(DNAME, validRecords[0])
  base.getFields(DNAME, [ 'target' ])
  base.getTypeId(DNAME, 39)

  base.toBind(DNAME, validRecords)
  base.toTinydns(DNAME, validRecords)

  base.fromBind(DNAME, validRecords)
  base.fromTinydns(DNAME, validRecords)

  for (const val of validRecords) {
    it.skip(`imports tinydns DNAME (generic) record (${val.owner})`, async function () {
      const r = new DNAME({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'owner', 'target', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
