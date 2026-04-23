import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import SPF from '../../rr/spf.js'

const defaults = { class: 'IN', ttl: 86400, type: 'SPF' }

const validRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    data: 'v=spf1 mx a include:mx.example.com -all',
    testB: 'example.com.\t86400\tIN\tSPF\t"v=spf1 mx a include:mx.example.com -all"\n',
    testT: ':example.com:99:v=spf1 mx a include\\072mx.example.com -all:86400::\n',
    testW:
      '076578616d706c6503636f6d000063000100015180002827763d73706631206d78206120696e636c7564653a6d782e6578616d706c652e636f6d202d616c6c',
  },
]

const invalidRecords = []

describe('SPF record', function () {
  base.valid(SPF, validRecords)
  base.invalid(SPF, invalidRecords)

  base.getDescription(SPF)
  base.getRFCs(SPF, validRecords[0])
  base.getFields(SPF, ['data'])
  base.getCanonical(SPF)
  base.getTypeId(SPF, 99)
  base.getTags(SPF)

  base.toBind(SPF, validRecords)
  base.toWire(SPF, validRecords)
  base.toTinydns(SPF, validRecords)

  base.fromBind(SPF, validRecords)
  base.fromTinydns(SPF, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns SPF (generic) record`, async function () {
      const r = SPF.fromTinydns(val.testT)
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'data', 'ttl']) {
        assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})

base.fromWire(SPF, validRecords)
