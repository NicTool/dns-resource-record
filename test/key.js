import { describe } from 'node:test'
import * as base from './base.js'

import KEY from '../rr/key.js'

const validRecords = [
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'KEY',
    flags: 256,
    protocol: 3,
    algorithm: 5,
    publickey: `( AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w== )`,
    testB:
      'example.com.\t3600\tIN\tKEY\t256\t3\t5\t( AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w== )\n',
    testW:
      '076578616d706c6503636f6d000019000100000e100086010003050103d22a6ca77f35b893206fd35e4c506d8378843709b97e041647e1bff43d8d64c649af1e371973c9e891fce3df519a8c840a63ee42a6d2ebddbb97035d215aa4e417b1fa45fa11a9741ea2098c1dfa5fb5feb332fd4bc8152089aef36ba644cce2413b3b72be18cbef8da253f4e93d2103866d9234a2e28df529a67d5468dbefe3',
  },
]

const invalidRecords = [
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'KEY',
    flags: 256,
    protocol: 3,
    algorithm: 99,
    publickey: 'AQPSK==',
    msg: /algorithm invalid/i,
  },
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'KEY',
    flags: 256,
    protocol: 3,
    algorithm: 5,
    publickey: '',
    msg: /publickey is required/i,
  },
]

describe('KEY record', function () {
  base.valid(KEY, validRecords)
  base.invalid(KEY, invalidRecords, { ttl: 3600 })

  base.getDescription(KEY)
  base.getRFCs(KEY, validRecords[0])
  base.getFields(KEY, ['flags', 'protocol', 'algorithm', 'publickey'])
  base.getCanonical(KEY)
  base.getTypeId(KEY, 25)
  base.getTags(KEY)

  base.toBind(KEY, validRecords)
  base.toWire(KEY, validRecords)
  base.toTinydns(KEY, validRecords)

  base.fromBind(KEY, validRecords)
  base.fromTinydns(KEY, validRecords)
})
