import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import URI from '../../rr/uri.js'

const validRecords = [
  {
    class: 'IN',
    owner: 'www.example.com.',
    type: 'URI',
    target: 'www2.example.com.',
    priority: 1,
    weight: 0,
    ttl: 3600,
    testB: 'www.example.com.\t3600\tIN\tURI\t1\t0\t"www2.example.com."\n',
    testT: ':www.example.com:256:\\000\\001\\000\\000www2.example.com.:3600::\n',
  },
  {
    class: 'IN',
    owner: '_http.github.dog.',
    type: 'URI',
    target: 'http://github.com/dog',
    priority: 2,
    weight: 100,
    ttl: 3600,
    testB: '_http.github.dog.\t3600\tIN\tURI\t2\t100\t"http://github.com/dog"\n',
    testT: ':_http.github.dog:256:\\000\\002\\000\\144http\\072\\057\\057github.com\\057dog:3600::\n',
  },
  {
    owner: '_http._tcp.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'URI',
    priority: 1,
    weight: 10,
    target: 'https://nictool.tnpi.net/',
    testB: '_http._tcp.nictool.tnpi.net.\t3600\tIN\tURI\t1\t10\t"https://nictool.tnpi.net/"\n',
    testT:
      ':_http._tcp.nictool.tnpi.net:256:\\000\\001\\000\\012https\\072\\057\\057nictool.tnpi.net\\057:3600::\n',
    testW:
      '055f68747470045f746370076e6963746f6f6c04746e7069036e6574000100000100000e10001d0001000a68747470733a2f2f6e6963746f6f6c2e746e70692e6e65742f',
  },
  {
    owner: '_ftp._tcp.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'URI',
    priority: 1,
    weight: 10,
    target: 'ftp://ftp.nictool.tnpi.net/',
    testB: '_ftp._tcp.nictool.tnpi.net.\t3600\tIN\tURI\t1\t10\t"ftp://ftp.nictool.tnpi.net/"\n',
    testT:
      ':_ftp._tcp.nictool.tnpi.net:256:\\000\\001\\000\\012ftp\\072\\057\\057ftp.nictool.tnpi.net\\057:3600::\n',
    testW:
      '045f667470045f746370076e6963746f6f6c04746e7069036e6574000100000100000e10001f0001000a6674703a2f2f6674702e6e6963746f6f6c2e746e70692e6e65742f',
  },
]

const invalidRecords = [
  {
    class: 'IN',
    owner: 'www.example.com.',
    type: 'URI',
    priority: 1,
    weight: 0,
    ttl: 3600,
    msg: /target is required/i,
  },
]

describe('URI record', function () {
  base.valid(URI, validRecords)
  base.invalid(URI, invalidRecords)

  base.getDescription(URI)
  base.getRFCs(URI, validRecords[0])
  base.getFields(URI, ['priority', 'weight', 'target'])
  base.getCanonical(URI)
  base.getTypeId(URI, 256)
  base.getTags(URI)

  base.toBind(URI, validRecords)
  base.toWire(URI, validRecords)
  base.toTinydns(URI, validRecords)

  base.fromBind(URI, validRecords)
  base.fromTinydns(URI, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns (generic) record`, async function () {
      const r = URI.fromTinydns(val.testT)
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'priority', 'weight', 'target', 'ttl']) {
        assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})

  base.fromWire(URI, validRecords)
