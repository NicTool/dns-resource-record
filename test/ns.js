
const assert = require('assert')

const base = require('./base')

const NS = require('../rr/ns')

const validRecords = [
  {
    owner: 'example.com.',
    ttl  : 3600,
    class: 'IN',
    type : 'NS',
    dname: 'ns1.example.com.',
    testB: 'example.com.\t3600\tIN\tNS\tns1.example.com.\n',
    testT: '&example.com::ns1.example.com:3600::\n',
  },
]

const invalidRecords = [
  {
    owner: 'example.com',
    dname: '1.2.3.4',  // FQDN required
  },
]

describe('NS record', function () {
  base.valid(NS, validRecords)
  base.invalid(NS, invalidRecords, { ttl: 3600 })

  base.getDescription(NS)
  base.getRFCs(NS, validRecords[0])
  base.getFields(NS, [ 'dname' ])
  base.getTypeId(NS, 2)

  base.toBind(NS, validRecords)
  base.toTinydns(NS, validRecords)

  base.fromBind(NS, validRecords)
  base.fromTinydns(NS, validRecords)

  for (const val of validRecords) {
    it.skip(`imports tinydns NS (&) record (${val.owner})`, async function () {
      const r = new NS({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'owner', 'dname', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
