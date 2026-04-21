import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from './base.js'

import MX from '../rr/mx.js'

const defaults = { class: 'IN', ttl: 3600, type: 'MX', preference: 0 }

const validRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    preference: 0,
    exchange: 'mail.example.com.',
    testB: 'test.example.com.\t3600\tIN\tMX\t0\tmail.example.com.\n',
    testT: '@test.example.com::mail.example.com:0:3600::\n',
    testW: '0474657374076578616d706c6503636f6d00000f000100000e1000140000046d61696c076578616d706c6503636f6d00',
  },
  {
    ...defaults,
    owner: 'www.example.com.',
    ttl: 86400,
    preference: 0,
    exchange: '.', // null MX, RFC 7505
    testB: 'www.example.com.\t86400\tIN\tMX\t0\t.\n',
    testT: '@www.example.com::.:0:86400::\n',
    testW: '03777777076578616d706c6503636f6d00000f0001000151800003000000',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'MX',
    preference: 10,
    exchange: 'mail.nictool.tnpi.net.',
    testW:
      '076e6963746f6f6c04746e7069036e657400000f000100000e100019000a046d61696c076e6963746f6f6c04746e7069036e657400',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'MX',
    preference: 20,
    exchange: 'mail.tnpi.net.',
    testW: '076e6963746f6f6c04746e7069036e657400000f000100000e1000110014046d61696c04746e7069036e657400',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    exchange: 'not-full-qualified.example.com',
    msg: /exchange must be fully qualified/,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    exchange: '192.0.2.1',
    msg: /exchange must be a FQDN/,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    exchange: '-blah',
    msg: /exchange must be fully qualified/,
  },
]

describe('MX record', function () {
  base.valid(MX, validRecords)
  base.invalid(MX, invalidRecords)

  base.getDescription(MX)
  base.getRFCs(MX, validRecords[0])
  base.getFields(MX, ['preference', 'exchange'])
  base.getCanonical(MX)
  base.getTypeId(MX, 15)
  base.getTags(MX)

  base.toBind(MX, validRecords)
  base.toWire(MX, validRecords)
  base.toTinydns(MX, validRecords)

  base.fromBind(MX, validRecords)
  base.fromTinydns(MX, validRecords)

  for (const val of validRecords) {
    if (!val.testT) continue
    it(`imports tinydns MX (@) record (${val.owner})`, async function () {
      const r = new MX({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'exchange', 'preference', 'ttl']) {
        assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
