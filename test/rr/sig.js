import { describe } from 'node:test'

import * as base from '../base.js'

import SIG from '../../rr/sig.js'

const defaults = { class: 'IN', ttl: 3600, type: 'SIG' }

const validRecords = [
  {
    ...defaults,
    owner: 'example.com.',
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
      'example.com.\t3600\tIN\tSIG\t1\t5\t1\t3600\t1678886400\t1678886400\t12345\texample.com.\t( AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w== )',
    testT:
      ':example.com:24:\\000\\001\\005\\001\\000\\000\\016\\020\\144\\021\\306\\000\\144\\021\\306\\000\\060\\071\\007example\\003com\\000AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w==:3600::\n',
    testW:
      '076578616d706c6503636f6d000018000100000e1000d50001050100000e106411c6006411c6003039076578616d706c6503636f6d00415150534b6d796e667a57346b7942763031354d55473244654951332043626c2b42425a4834622f305059316b786b6d76486a635a63386e6f206b667a6a333147616a49514b592b354370744c723362755841313068205771546b4637483652666f52715851656f676d4d486670667466367a204d76314c794255676961377a61365a457a4f4a424f7a747976686a4c2037343269552f547050534544686d32534e4b4c696a665570706e315520614e767634773d3d',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    algorithm: 5,
    labels: 1,
    'original ttl': 3600,
    'signature expiration': 1678886400,
    'signature inception': 1678886400,
    'key tag': 12345,
    'signers name': 'example.com.',
    signature: 'AQPSK==',
    msg: /'type covered' is required/i,
  },
]

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
  base.getCanonical(SIG)
  base.getTypeId(SIG, 24)
  base.getTags(SIG)

  base.toBind(SIG, validRecords)
  base.toWire(SIG, validRecords)
  base.toTinydns(SIG, validRecords)

  base.fromBind(SIG, validRecords)
  base.fromTinydns(SIG, validRecords)
})
