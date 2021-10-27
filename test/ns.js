
const assert = require('assert')

const base = require('./base')

const NS = require('../rr/ns')

const validRecords = [
  {
    class: 'IN',
    name : 'example.com',
    type : 'NS',
    dname: 'ns1.example.com.',
    ttl  : 3600,
    testB: 'example.com\t3600\tIN\tNS\tns1.example.com.\n',
    testT: '&example.com::ns1.example.com.:3600::\n',
  },
]

const invalidRecords = [
  {
    class: 'IN',
    name : 'example.com',
    type : 'NS',
    dname: '1.2.3.4',  // FQDN required
    ttl  : 3600,
  },
]

describe('NS record', function () {
  base.valid(NS, validRecords)
  base.invalid(NS, invalidRecords)

  base.toBind(NS, validRecords)
  base.toTinydns(NS, validRecords)

  base.fromTinydns(NS, validRecords)

  base.getRFCs(NS, validRecords[0])

  for (const val of validRecords) {
    it.skip(`imports tinydns NS (&) record (${val.name})`, async function () {
      const r = new NS({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'dname', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
