import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from './base.js'

import NS from '../rr/ns.js'

const defaults = { class: 'IN', ttl: 3600, type: 'NS' }

const validRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    dname: 'ns1.example.com.',
    testB: 'example.com.\t3600\tIN\tNS\tns1.example.com.\n',
    testT: '&example.com::ns1.example.com:3600::\n',
    testW: '076578616d706c6503636f6d000002000100000e100011036e7331076578616d706c6503636f6d00',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'NS',
    dname: 'ns1.tnpi.net.',
    testW: '076e6963746f6f6c04746e7069036e6574000002000100000e10000e036e733104746e7069036e657400',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'NS',
    dname: 'ns2.tnpi.net.',
    testW: '076e6963746f6f6c04746e7069036e6574000002000100000e10000e036e733204746e7069036e657400',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    dname: '1.2.3.4', // FQDN required
    msg: /dname must be fully qualified/,
  },
]

describe('NS record', function () {
  base.valid(NS, validRecords)
  base.invalid(NS, invalidRecords)

  base.getDescription(NS)
  base.getRFCs(NS, validRecords[0])
  base.getFields(NS, ['dname'])
  base.getCanonical(NS)
  base.getTypeId(NS, 2)
  base.getTags(NS)

  base.toBind(NS, validRecords)
  base.toWire(NS, validRecords)
  base.toTinydns(NS, validRecords)

  base.fromBind(NS, validRecords)
  base.fromTinydns(NS, validRecords)

  for (const val of validRecords) {
    if (!val.testT) continue
    it(`imports tinydns NS (&) record (${val.owner})`, function () {
      const r = new NS({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'dname', 'ttl']) {
        assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
