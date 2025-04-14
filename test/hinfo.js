import assert from 'node:assert/strict'

import * as base from './base.js'

import HINFO from '../rr/hinfo.js'

const defaults = { class: 'IN', ttl: 86400, type: 'HINFO' }

const validRecords = [
  {
    ...defaults,
    owner: 'server-under-my-desk.example.com.',
    cpu: 'PDP-11/73',
    os: 'UNIX',
    testB:
      'server-under-my-desk.example.com.\t86400\tIN\tHINFO\t"PDP-11/73"\t"UNIX"\n',
    testT:
      ':server-under-my-desk.example.com:13:\\011PDP-11/73\\004UNIX:86400::\n',
  },
  {
    ...defaults,
    owner: 'sri-nic.arpa.',
    cpu: 'DEC-2060',
    os: 'TOPS20',
    testB: 'sri-nic.arpa.\t86400\tIN\tHINFO\t"DEC-2060"\t"TOPS20"\n',
    testT: ':sri-nic.arpa:13:\\010DEC-2060\\006TOPS20:86400::\n',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'www.example.com.',
    address: '',
    msg: /Cannot read proper/,
  },
]

describe('HINFO record', function () {
  base.valid(HINFO, validRecords)
  base.invalid(HINFO, invalidRecords)

  base.getDescription(HINFO)
  base.getRFCs(HINFO, validRecords[0])
  base.getFields(HINFO, ['cpu', 'os'])
  base.getTypeId(HINFO, 13)

  base.toBind(HINFO, validRecords)
  base.toTinydns(HINFO, validRecords)

  base.fromBind(HINFO, validRecords)
  base.fromTinydns(HINFO, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns HINFO (generic) record (${val.owner})`, async function () {
      const r = new HINFO({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'address', 'ttl']) {
        assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }

  for (const f of ['os', 'cpu']) {
    it(`rejects ${f} value longer than 255 chars`, async () => {
      const tooLong =
        'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz'
      const r = new HINFO(null)
      try {
        assert.fail(r[`set${r.ucfirst(f)}`](tooLong))
      } catch (e) {
        assert.ok(/cannot exceed 255 chars/.test(e.message))
      }
    })
  }
})
