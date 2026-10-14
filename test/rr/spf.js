import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import SPF from '../../rr/spf.js'

const defaults = { ttl: 86400 }

const valid = [
  {
    ...defaults,
    owner: 'example.com.',
    data: 'v=spf1 mx a include:mx.example.com -all',
    testB: 'example.com.\t86400\tIN\tSPF\t"v=spf1 mx a include:mx.example.com -all"\n',
    testT: ":example.com:99:'v=spf1 mx a include\\072mx.example.com -all:86400::\n",
    testW:
      '076578616d706c6503636f6d000063000100015180002827763d73706631206d78206120696e636c7564653a6d782e6578616d706c652e636f6d202d616c6c',
  },
]

const invalid = []

describe('SPF record', function () {
  base.suite(SPF, { typeId: 99, fields: ['data'], valid, invalid })

  it('toTinydns accepts array-form data (multi-string charstrs)', function () {
    const r = new SPF({ ...defaults, owner: 'example.com.', data: ['v=spf1 ', 'mx -all'] })
    const line = r.toTinydns()
    assert.match(line, /^:example\.com:99:/, 'tinydns has no SPF line')
    assert.deepEqual(SPF.fromTinydns(line).get('data'), ['v=spf1 ', 'mx -all'], 'string boundaries survive')
  })
})
