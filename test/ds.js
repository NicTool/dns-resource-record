import { describe } from 'node:test'
import * as base from './base.js'

import DS from '../rr/ds.js'

const defaults = { class: 'IN', ttl: 3600, type: 'DS', 'key tag': 60485, algorithm: 5, 'digest type': 1 }

const validRecords = [
  {
    ...defaults,
    owner: 'dskey.example.com.',
    digest: '2BB183AF5F22588179A53B0A98631FAD1A292118',
    testB: 'dskey.example.com.\t3600\tIN\tDS\t60485\t5\t1\t2BB183AF5F22588179A53B0A98631FAD1A292118\n',
    testT:
      ':dskey.example.com:43:\\354\\105\\005\\001\\053\\261\\203\\257\\137\\042\\130\\201\\171\\245\\073\\012\\230\\143\\037\\255\\032\\051\\041\\030:3600::\n',
    testW:
      '0564736b6579076578616d706c6503636f6d00002b000100000e100018ec4505012bb183af5f22588179a53b0a98631fad1a292118',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    algorithm: 6,
    msg: /algorithm/,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    'key tag': 65536,
    msg: /must be a 16-bit integer/,
  },
]

describe('DS record', function () {
  base.valid(DS, validRecords)
  base.invalid(DS, invalidRecords)

  base.getDescription(DS)
  base.getRFCs(DS, validRecords[0])
  base.getFields(DS, ['key tag', 'algorithm', 'digest type', 'digest'])
  base.getCanonical(DS)
  base.getTypeId(DS, 43)
  base.getTags(DS)

  base.toBind(DS, validRecords)
  base.toWire(DS, validRecords)
  base.toTinydns(DS, validRecords)

  base.fromBind(DS, validRecords)
  base.fromTinydns(DS, validRecords)
})
