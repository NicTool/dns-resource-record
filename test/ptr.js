
const assert = require('assert')

const base = require('./base')

const PTR = require('../rr/ptr')

const validRecords = [
  {
    class: 'IN',
    name : '2.2.0.192.in-addr.arpa',
    type : 'PTR',
    dname: 'dhcp.example.com.',
    ttl  : 86400,
    testB: '2.2.0.192.in-addr.arpa\t86400\tIN\tPTR\tdhcp.example.com.\n',
    testT: '^2.2.0.192.in-addr.arpa:dhcp.example.com.:86400::\n',
  },
]

const invalidRecords = [
  {
    class: 'IN',
    name : 'example.com',
    type : 'PTR',
    dname: '192.0.2.4',  // FQDN required
    ttl  : 3600,
  },
]

describe('PTR record', function () {
  base.valid(PTR, validRecords)
  base.invalid(PTR, invalidRecords)

  base.getRFCs(PTR, validRecords[0])

  base.toBind(PTR, validRecords)
  base.toTinydns(PTR, validRecords)

  base.fromBind(PTR, validRecords)
  base.fromTinydns(PTR, validRecords)

  for (const val of validRecords) {

    it.skip(`imports tinydns PTR (^) record (${val.name})`, async function () {
      const r = new PTR({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'dname', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
