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
  },
]

const invalidRecords = []

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
  base.getTypeId(RRSIG, 46)

  // base.toBind(RRSIG, validRecords)
  base.toTinydns(RRSIG, validRecords)

  base.fromBind(RRSIG, validRecords)
  base.fromTinydns(RRSIG, validRecords)
})
