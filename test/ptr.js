import assert from 'node:assert/strict'

import * as base from './base.js'

import PTR from '../rr/ptr.js'

const defaults = { class: 'IN', ttl: 86400, type: 'PTR' }

const validRecords = [
  {
    ...defaults,
    owner: '2.2.0.192.in-addr.arpa.',
    dname: 'dhcp.example.com.',
    testB: '2.2.0.192.in-addr.arpa.\t86400\tIN\tPTR\tdhcp.example.com.\n',
    testT: '^2.2.0.192.in-addr.arpa:dhcp.example.com:86400::\n',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    dname: '192.0.2.4', // FQDN required
    msg: /dname must be fully qualified/,
  },
]

describe('PTR record', function () {
  base.valid(PTR, validRecords)
  base.invalid(PTR, invalidRecords)

  base.getDescription(PTR)
  base.getRFCs(PTR, validRecords[0])
  base.getFields(PTR, ['dname'])
  base.getTypeId(PTR, 12)

  base.toBind(PTR, validRecords)
  base.toTinydns(PTR, validRecords)

  base.fromBind(PTR, validRecords)
  base.fromTinydns(PTR, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns PTR (^) record (${val.owner})`, async function () {
      const r = new PTR({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'dname', 'ttl']) {
        assert.deepEqual(
          r.get(f),
          val[f],
          `${f}: ${r.get(f)} !== ${val[f]}`,
        )
      }
    })
  }
})
