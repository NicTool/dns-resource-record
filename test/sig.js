import { describe } from 'node:test'

import * as base from './base.js'

import SIG from '../rr/sig.js'

const defaults = { class: 'IN', ttl: 3600, type: 'SIG' }

const validRecords = [
  {
    owner: 'example.com.',
    ...defaults,
    'type covered': 1,
    algorithm: 5,
    labels: 1,
    'original ttl': 3600,
    'signature expiration': 1678886400,
    'signature inception': 1678886400,
    'key tag': 12345,
    'signers name': 'example.com.',
    signature:
      'AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w==',
    testB:
      'example.com.	3600	IN	SIG	1	5	1	3600	1678886400	1678886400	12345	example.com.	( AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w== )',
    // testT: ':example.com:24:\000\001\005\001\000\000\000\001\000\000\000\001\000\000\000\001\000\000\000\001\000\001AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w==:3600::',
  },
]

const invalidRecords = []

describe('SIG record', function () {
  base.valid(SIG, validRecords)
  base.invalid(SIG, invalidRecords)

  base.getDescription(SIG)
  base.getRFCs(SIG, validRecords[0])
  base.getFields(SIG, [
    'type covered',
    'algorithm',
    'labels',
    'original ttl',
    'signature expiration',
    'signature inception',
    'key tag',
    'signers name',
    'signature',
  ])
  base.getTypeId(SIG, 24)

  base.toBind(SIG, validRecords)
  base.toTinydns(SIG, validRecords)

  // base.fromBind(SIG, validRecords)
  // base.fromTinydns(SIG, validRecords)
})
