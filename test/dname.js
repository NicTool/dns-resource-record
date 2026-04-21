import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from './base.js'

import DNAME from '../rr/dname.js'

const defaults = { class: 'IN', ttl: 86400, type: 'DNAME' }

const validRecords = [
  {
    ...defaults,
    owner: '_tcp.example.com.',
    target: '_tcp.example.net.',
    testB: '_tcp.example.com.\t86400\tIN\tDNAME\t_tcp.example.net.\n',
    testT: ':_tcp.example.com:39:\\004\\137tcp\\007example\\003net\\000:86400::\n',
  },
  {
    owner: 'old.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'DNAME',
    target: 'new.tnpi.net.',
    testB: 'old.nictool.tnpi.net.\t3600\tIN\tDNAME\tnew.tnpi.net.\n',
    testT: ':old.nictool.tnpi.net:39:\\003new\\004tnpi\\003net\\000:3600::\n',
    testW: '036f6c64076e6963746f6f6c04746e7069036e6574000027000100000e10000e036e657704746e7069036e657400',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'spf.example.com.',
    target: '1.2.3.4', // FQDN required
    msg: /target must be a domain name/,
  },
]

describe('DNAME record', function () {
  base.valid(DNAME, validRecords)
  base.invalid(DNAME, invalidRecords)

  base.getDescription(DNAME)
  base.getRFCs(DNAME, validRecords[0])
  base.getFields(DNAME, ['target'])
  base.getCanonical(DNAME)
  base.getTypeId(DNAME, 39)
  base.getTags(DNAME)

  base.toBind(DNAME, validRecords)
  base.toWire(DNAME, validRecords)
  base.toTinydns(DNAME, validRecords)

  base.fromBind(DNAME, validRecords)
  base.fromTinydns(DNAME, validRecords)

  for (const val of validRecords) {
    if (!val.testT) continue
    it(`imports tinydns DNAME (generic) record (${val.owner})`, async function () {
      const r = new DNAME({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'target', 'ttl']) {
        assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
