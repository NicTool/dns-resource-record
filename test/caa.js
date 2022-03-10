
const assert = require('assert')

const base = require('./base')

const CAA = require('../rr/caa')

const validRecords = [
  {
    class: 'IN',
    name : 'ns1.example.com',
    type : 'CAA',
    flags: 0,
    tag  : 'issue',
    value: 'letsencrypt.org',
    ttl  : 3600,
    testB: `ns1.example.com\t3600\tIN\tCAA\t0\tissue\t"letsencrypt.org"\n`,
    testT: ':ns1.example.com:257:\\000\\005issueletsencrypt.org:3600::\n',
  },
  {
    class: 'IN',
    name : 'ns2.example.com',
    type : 'CAA',
    flags: 0,
    tag  : 'issue',
    value: '"lets crypt.org"',
    ttl  : 3600,
    testB: `ns2.example.com\t3600\tIN\tCAA\t0\tissue\t"lets crypt.org"\n`,
    testT: ':ns2.example.com:257:\\000\\005issue"lets crypt.org":3600::\n',
  },
  {
    name : 'example.net',
    type : 'CAA',
    ttl  : 86400,
    flags: 0,
    tag  : 'issuewild',
    value: 'letsencrypt.org',
    testB: 'example.net\t86400\tIN\tCAA\t0\tissuewild\t"letsencrypt.org"\n',
    testT: ':example.net:257:\\000\\011issuewildletsencrypt.org:86400::\n',
  },
]

const invalidRecords = [
  {
    class: 'IN',
    name : 'example.com',
    type : 'CAA',
    flags: 1,
    tag  : 'issue',
    value: 'lets encrypt.org', // spaces aren't allowed unless quoted
    ttl  : 3600,
  },
]

describe('CAA record', function () {
  base.valid(CAA, validRecords)
  base.invalid(CAA, invalidRecords)

  base.getRFCs(CAA, validRecords[0])
  base.getFields(CAA, [ 'flags', 'tag' ])

  base.toBind(CAA, validRecords)
  base.toTinydns(CAA, validRecords)

  base.fromBind(CAA, validRecords)
  base.fromTinydns(CAA, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns CAA (generic) record`, async function () {
      const r = new CAA({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'flags', 'tag', 'value', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
