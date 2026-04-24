import { describe } from 'node:test'
import * as base from '../base.js'

import DNSKEY from '../../rr/dnskey.js'

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
    testB:
      'nictool.tnpi.net.\t3600\tIN\tDNSKEY\t256\t3\t5\tAQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==\n',
    testT:
      ':nictool.tnpi.net:48:\\001\\000\\003\\005\\001\\003\\322\\052l\\247\\1775\\270\\223\\040o\\323\\136LPm\\203x\\2047\\011\\271\\176\\004\\026G\\341\\277\\364\\075\\215d\\306I\\257\\0367\\031s\\311\\350\\221\\374\\343\\337Q\\232\\214\\204\\012c\\356B\\246\\322\\353\\335\\273\\227\\003\\135\\041Z\\244\\344\\027\\261\\372E\\372\\021\\251t\\036\\242\\011\\214\\035\\372\\137\\265\\376\\2632\\375K\\310\\025\\040\\211\\256\\363k\\246D\\314\\342A\\073\\073r\\276\\030\\313\\357\\215\\242S\\364\\351\\075\\041\\003\\206m\\2224\\242\\342\\215\\365\\051\\246\\175Th\\333\\357\\343:3600::\n',
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
  {
    ...defaults,
    owner: 'test.example.com.',
    flags: 1, // valid 16-bit int but not in set {0,256,257}
    msg: /flags must be in the set/,
  },
  {
    bindline: 'invalid dnskey line',
    msg: /unable to parse DNSKEY/,
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
  base.fromWire(DNSKEY, validRecords)
})
