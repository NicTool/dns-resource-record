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
  },
  {
    ...defaults,
    owner: 'www.example.com.',
    ttl: 86400,
    preference: 0,
    exchange: '.', // null MX, RFC 7505
    testB: 'www.example.com.\t86400\tIN\tMX\t0\t.\n',
    testT: '@www.example.com::.:0:86400::\n',
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
  base.getTypeId(MX, 15)

  base.toBind(MX, validRecords)
  base.toTinydns(MX, validRecords)

  base.fromBind(MX, validRecords)
  base.fromTinydns(MX, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns MX (@) record (${val.owner})`, async function () {
      const r = new MX({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'exchange', 'preference', 'ttl']) {
        assert.deepEqual(
          r.get(f),
          val[f],
          `${f}: ${r.get(f)} !== ${val[f]}`,
        )
      }
    })
  }
})
