
const assert = require('assert')

const base = require('./base')

const CAA = require('../rr/caa')

const validRecords = [
  {
    owner: 'ns1.example.com.',
    ttl  : 3600,
    class: 'IN',
    type : 'CAA',
    flags: 0,
    tag  : 'issue',
    value: 'http://letsencrypt.org',
    testB: `ns1.example.com.\t3600\tIN\tCAA\t0\tissue\t"http://letsencrypt.org"\n`,
    testT: ':ns1.example.com:257:\\000\\005issue"http\\072\\057\\057letsencrypt.org":3600::\n',
  },
  {
    owner: 'ns2.example.com.',
    ttl  : 3600,
    class: 'IN',
    type : 'CAA',
    flags: 0,
    tag  : 'issue',
    value: 'mailto:lets-crypt.org',
    testB: `ns2.example.com.\t3600\tIN\tCAA\t0\tissue\t"mailto:lets-crypt.org"\n`,
    testT: ':ns2.example.com:257:\\000\\005issue"mailto\\072lets-crypt.org":3600::\n',
  },
  {
    owner: 'example.net.',
    ttl  : 86400,
    type : 'CAA',
    flags: 0,
    tag  : 'issuewild',
    value: 'https://letsencrypt.org',
    testB: 'example.net.\t86400\tIN\tCAA\t0\tissuewild\t"https://letsencrypt.org"\n',
    testT: ':example.net:257:\\000\\011issuewild"https\\072\\057\\057letsencrypt.org":86400::\n',
  },
]

const invalidRecords = [
  {
    owner: 'example.com',
    flags: 128,
    tag  : 'issue',
    value: 'letsencrypt.org', // missing iodef prefix
  },
  {
    owner: 'example.com',
    flags: 128,
    tag  : 'invalid', // invalid
    value: 'http://letsencrypt.org',
  },
  {
    owner: 'example.com',
    flags: 15,  // invalid
    tag  : 'issue',
    value: 'http://letsencrypt.org',
  },
]

describe('CAA record', function () {
  base.valid(CAA, validRecords)
  base.invalid(CAA, invalidRecords, { ttl: 3600 })

  base.getDescription(CAA)
  base.getRFCs(CAA, validRecords[0])
  base.getFields(CAA, [ 'flags', 'tag', 'value' ])
  base.getTypeId(CAA, 257)

  base.toBind(CAA, validRecords)
  base.toTinydns(CAA, validRecords)

  base.fromBind(CAA, validRecords)
  base.fromTinydns(CAA, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns CAA (generic) record`, async function () {
      const r = new CAA({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'owner', 'flags', 'tag', 'value', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
