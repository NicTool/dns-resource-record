
const assert = require('assert')

const base = require('./base')

const SRV = require('../rr/srv')

const validRecords = [
  {
    class   : 'IN',
    name    : '_imaps._tcp.example.com',
    type    : 'SRV',
    target  : 'mail.example.com.',
    priority: 1,
    weight  : 0,
    port    : 993,
    ttl     : 3600,
    testB   : '_imaps._tcp.example.com\t3600\tIN\tSRV\t1\t0\t993\tmail.example.com.\n',
    testT   : ':_imaps._tcp.example.com:33:\\000\\001\\000\\000\\003\\341\\004mail\\007example\\003com\\000:3600::\n',
  },
]

const invalidRecords = [
  {
    class : 'IN',
    name  : 'test.example.com',
    type  : 'SRV',
    target: 'not-full-qualified.example.com',
    ttl   : 3600,
  },
  {
    class : 'IN',
    name  : 'test.example.com',
    type  : 'SRV',
    target: '192.168.0.1',
    ttl   : 3600,
  },
]

describe('SRV record', function () {
  base.valid(SRV, validRecords)
  base.invalid(SRV, invalidRecords)

  base.getRFCs(SRV, validRecords[0])
  base.getFields(SRV, [ 'priority', 'weight', 'port', 'target' ])

  base.toBind(SRV, validRecords)
  base.toTinydns(SRV, validRecords)

  base.fromBind(SRV, validRecords)
  base.fromTinydns(SRV, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns SRV (generic) record (${val.name})`, async function () {
      const r = new SRV({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'target', 'priority', 'weight', 'port', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }

  it(`imports tinydns SRV (S) record`, async function () {
    const val = validRecords[0]
    const r = new SRV({ tinyline: 'S_imaps._tcp.example.com:mail.example.com:993:1:0:3600::' })
    if (process.env.DEBUG) console.dir(r)
    for (const f of [ 'name', 'target', 'priority', 'weight', 'port', 'ttl' ]) {
      assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
    }
  })
})
