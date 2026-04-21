import { describe } from 'node:test'
import * as base from './base.js'

import DNSKEY from '../rr/dnskey.js'

const defaults = { class: 'IN', ttl: 3600, type: 'DNSKEY', flags: 256, protocol: 3, algorithm: 5 }

const validRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    publickey: 'AQPSKAsj8A==',
    testB: 'example.com.\t3600\tIN\tDNSKEY\t256\t3\t5\tAQPSKAsj8A==\n',
    testT: ':example.com:48:\\001\\000\\003\\005\\001\\003\\322\\050\\013\\043\\360:3600::\n',
    testW: '076578616d706c6503636f6d000030000100000e10000b010003050103d2280b23f0',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'DNSKEY',
    flags: 256,
    protocol: 3,
    algorithm: 5,
    publickey:
      'AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==',
    testW:
      '076e6963746f6f6c04746e7069036e6574000030000100000e100086010003050103d22a6ca77f35b893206fd35e4c506d8378843709b97e041647e1bff43d8d64c649af1e371973c9e891fce3df519a8c840a63ee42a6d2ebddbb97035d215aa4e417b1fa45fa11a9741ea2098c1dfa5fb5feb332fd4bc8152089aef36ba644cce2413b3b72be18cbef8da253f4e93d2103866d9234a2e28df529a67d5468dbefe3',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    algorithm: 257, // invalid
    msg: /algorithm must be a 8-bit integer/,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    flags: 65536,
    msg: /flags must be a 16-bit integer/,
  },
]

describe('DNSKEY record', function () {
  base.valid(DNSKEY, validRecords)
  base.invalid(DNSKEY, invalidRecords)

  base.getDescription(DNSKEY)
  base.getRFCs(DNSKEY, validRecords[0])
  base.getFields(DNSKEY, ['flags', 'protocol', 'algorithm', 'publickey'])
  base.getCanonical(DNSKEY)
  base.getTypeId(DNSKEY, 48)
  base.getTags(DNSKEY)

  base.toBind(DNSKEY, validRecords)
  base.toWire(DNSKEY, validRecords)
  base.toTinydns(DNSKEY, validRecords)

  base.fromBind(DNSKEY, validRecords)
  base.fromTinydns(DNSKEY, validRecords)
})
