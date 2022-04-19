
import assert from 'assert'

import * as base from './base.js'

import SRV from '../rr/srv.js'

const defaults = { class: 'IN', ttl: 3600, type: 'SRV' }

const validRecords = [
  {
    owner   : '_imaps._tcp.example.com.',
    ...defaults,
    priority: 1,
    weight  : 0,
    port    : 993,
    target  : 'mail.example.com.',
    testB   : '_imaps._tcp.example.com.\t3600\tIN\tSRV\t1\t0\t993\tmail.example.com.\n',
    testT   : ':_imaps._tcp.example.com:33:\\000\\001\\000\\000\\003\\341\\004mail\\007example\\003com\\000:3600::\n',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner : 'test.example.com.',
    target: 'not-full-qualified.example.com',
    msg   : /must be a 16-bit integer/,
  },
  {
    ...defaults,
    owner : 'test.example.com.',
    target: '192.168.0.1',
    msg   : /must be a 16-bit integer/,
  },
]

describe('SRV record', function () {
  base.valid(SRV, validRecords)
  base.invalid(SRV, invalidRecords)

  base.getDescription(SRV)
  base.getRFCs(SRV, validRecords[0])
  base.getFields(SRV, [ 'priority', 'weight', 'port', 'target' ])
  base.getTypeId(SRV, 33)

  base.toBind(SRV, validRecords)
  base.toTinydns(SRV, validRecords)

  base.fromBind(SRV, validRecords)
  base.fromTinydns(SRV, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns SRV (generic) record (${val.owner})`, async function () {
      const r = new SRV({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'owner', 'target', 'priority', 'weight', 'port', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }

  it(`imports tinydns SRV (S) record`, async function () {
    const val = validRecords[0]
    const r = new SRV({ tinyline: 'S_imaps._tcp.example.com:mail.example.com:993:1:0:3600::' })
    if (process.env.DEBUG) console.dir(r)
    for (const f of [ 'owner', 'target', 'priority', 'weight', 'port', 'ttl' ]) {
      assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
    }
  })
})
