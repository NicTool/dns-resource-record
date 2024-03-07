import assert from 'assert'

import * as base from './base.js'

import URI from '../rr/uri.js'

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
    testT:
      ':www.example.com:256:\\000\\001\\000\\000www2.example.com.:3600::\n',
  },
  {
    class: 'IN',
    owner: '_http.github.dog.',
    type: 'URI',
    target: 'http://github.com/dog',
    priority: 2,
    weight: 100,
    ttl: 3600,
    testB:
      '_http.github.dog.\t3600\tIN\tURI\t2\t100\t"http://github.com/dog"\n',
    testT:
      ':_http.github.dog:256:\\000\\002\\000\\144http\\072\\057\\057github.com\\057dog:3600::\n',
  },
]

const invalidRecords = []

describe('URI record', function () {
  base.valid(URI, validRecords)
  base.invalid(URI, invalidRecords)

  base.getDescription(URI)
  base.getRFCs(URI, validRecords[0])
  base.getFields(URI, ['priority', 'weight', 'target'])
  base.getTypeId(URI, 256)

  base.toBind(URI, validRecords)
  base.toTinydns(URI, validRecords)

  base.fromBind(URI, validRecords)
  base.fromTinydns(URI, validRecords)

  for (const val of validRecords) {
    it.skip(`imports tinydns (generic) record`, async function () {
      const r = new URI({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'priority', 'weight', 'target', 'ttl']) {
        assert.deepStrictEqual(
          r.get(f),
          val[f],
          `${f}: ${r.get(f)} !== ${val[f]}`,
        )
      }
    })
  }
})
