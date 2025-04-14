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
  base.getTypeId(NS, 2)

  base.toBind(NS, validRecords)
  base.toTinydns(NS, validRecords)

  base.fromBind(NS, validRecords)
  base.fromTinydns(NS, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns NS (&) record (${val.owner})`, function () {
      const r = new NS({ tinyline: val.testT })
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
