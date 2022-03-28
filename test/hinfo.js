
const assert = require('assert')

const base = require('./base')

const HINFO = require('../rr/hinfo')

const validRecords = [
  {
    class: 'IN',
    type : 'HINFO',
    owner: 'server-under-my-desk.example.com.',
    cpu  : 'PDP-11/73',
    os   : 'UNIX',
    ttl  : 86400,
    testB: 'server-under-my-desk.example.com.\t86400\tIN\tHINFO\t"PDP-11/73"\t"UNIX"\n',
    // testT : ':server-under-my-desk:13: :86400::\n',
  },
  {
    class: 'IN',
    type : 'HINFO',
    owner: 'sri-nic.arpa.',
    cpu  : 'DEC-2060',
    os   : 'TOPS20',
    ttl  : 86400,
    testB: 'sri-nic.arpa.\t86400\tIN\tHINFO\t"DEC-2060"\t"TOPS20"\n',
    // testT : ':server-under-my-desk:13: :86400::\n',
  },
]

const invalidRecords = [
  {
    owner  : 'www.example.com',
    type   : 'HINFO',
    address: '',
    // ttl    : 3600,
  },
]

describe('HINFO record', function () {
  base.valid(HINFO, validRecords)
  base.invalid(HINFO, invalidRecords)

  base.getDescription(HINFO)
  base.getRFCs(HINFO, validRecords[0])
  base.getFields(HINFO, [ 'cpu', 'os' ])
  base.getTypeId(HINFO, 13)

  base.toBind(HINFO, validRecords)
  // base.toTinydns(HINFO, validRecords)

  // base.fromBind(HINFO, validRecords)
  // base.fromTinydns(HINFO, validRecords)

  for (const val of validRecords) {
    it.skip(`imports tinydns HINFO (generic) record (${val.owner})`, async function () {
      const r = new HINFO({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'owner', 'address', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }

  for (const f of [ 'os', 'cpu' ]) {
    it(`rejects ${f} value longer than 255 chars`, async () => {
      const tooLong = 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz'
      const r = new HINFO(null)
      try {
        assert.fail(r[`set${r.ucfirst(f)}`](tooLong))
      }
      catch (e) {
        assert.equal(e.message, `HINFO ${f} cannot exceed 255 chars`)
      }
    })
  }
})
