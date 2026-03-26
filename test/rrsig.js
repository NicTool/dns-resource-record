import { describe } from 'node:test'

import * as base from './base.js'

import RRSIG from '../rr/rrsig.js'

const defaults = { class: 'IN', ttl: 3600, type: 'RRSIG' }

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
    signature: 'dummysignature==',
    testB:
      'example.com.\t3600\tIN\tRRSIG\t1\t5\t1\t3600\t1678886400\t1678886400\t12345\texample.com.\tdummysignature==\n',
    testT:
      ':example.com:46:\\000\\001\\005\\001\\000\\000\\016\\020\\144\\021\\306\\000\\144\\021\\306\\000\\060\\071\\007example\\003com\\000dummysignature==:3600::\n',
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
    signature: 'dummysignature==',
    msg: /'type covered' is required/i,
  },
  {
    ...defaults,
    owner: 'example.com.',
    'type covered': 1,
    algorithm: 99,
    labels: 1,
    'original ttl': 3600,
    'signature expiration': 1678886400,
    'signature inception': 1678886400,
    'key tag': 12345,
    'signers name': 'example.com.',
    signature: 'dummysignature==',
    msg: /algorithm invalid/i,
  },
]

describe('RRSIG record', function () {
  base.valid(RRSIG, validRecords)
  base.invalid(RRSIG, invalidRecords)

  base.getDescription(RRSIG)
  base.getRFCs(RRSIG, validRecords[0])
  base.getFields(RRSIG, [
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
  base.getCanonical(RRSIG)
  base.getTypeId(RRSIG, 46)
  base.getTags(RRSIG)

  base.toBind(RRSIG, validRecords)
  base.toWire(RRSIG, validRecords)
  base.toTinydns(RRSIG, validRecords)

  base.fromBind(RRSIG, validRecords)
  base.fromTinydns(RRSIG, validRecords)
})
