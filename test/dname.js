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
    testT:
      ':_tcp.example.com:39:\\004\\137tcp\\007example\\003net\\000:86400::\n',
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
  base.getTypeId(DNAME, 39)

  base.toBind(DNAME, validRecords)
  base.toTinydns(DNAME, validRecords)

  base.fromBind(DNAME, validRecords)
  base.fromTinydns(DNAME, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns DNAME (generic) record (${val.owner})`, async function () {
      const r = new DNAME({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'target', 'ttl']) {
        assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
