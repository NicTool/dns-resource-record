import assert from 'node:assert/strict'

import * as base from './base.js'

import SPF from '../rr/spf.js'

const defaults = { class: 'IN', ttl: 86400, type: 'SPF' }

const validRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    data: 'v=spf1 mx a include:mx.example.com -all',
    testB:
      'example.com.\t86400\tIN\tSPF\t"v=spf1 mx a include:mx.example.com -all"\n',
    testT:
      ':example.com:99:v=spf1 mx a include\\072mx.example.com -all:86400::\n',
  },
]

const invalidRecords = []

describe('SPF record', function () {
  base.valid(SPF, validRecords)
  base.invalid(SPF, invalidRecords)

  base.getDescription(SPF)
  base.getRFCs(SPF, validRecords[0])
  base.getFields(SPF, ['data'])
  base.getTypeId(SPF, 99)

  base.toBind(SPF, validRecords)
  base.toTinydns(SPF, validRecords)

  base.fromBind(SPF, validRecords)
  base.fromTinydns(SPF, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns SPF (generic) record`, async function () {
      const r = new SPF({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'data', 'ttl']) {
        assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
