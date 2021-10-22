
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
    testR: `ns1.example.com\t3600\tIN\tCAA\t0\tissue\t"letsencrypt.org"\n`,
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
    testR: `ns2.example.com\t3600\tIN\tCAA\t0\tissue\t"lets crypt.org"\n`,
    testT: ':ns2.example.com:257:\\000\\005issue"lets crypt.org":3600::\n',
  },
  {
    name : 'example.net',
    type : 'CAA',
    ttl  : 86400,
    flags: 0,
    tag  : 'issuewild',
    value: 'letsencrypt.org',
    testR: 'example.net\t86400\tIN\tCAA\t0\tissuewild\t"letsencrypt.org"\n',
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

  for (const val of validRecords) {
    it(`converts to BIND format ${val.name}`, async function () {
      const r = new CAA(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it(`converts to tinydns format ${val.name}`, async function () {
      const r = new CAA(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testT)
    })
  }
})
