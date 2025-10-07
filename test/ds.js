import * as base from './base.js'

import DS from '../rr/ds.js'

const defaults = { class: 'IN', ttl: 3600, type: 'DS' }

const validRecords = [
  {
    ...defaults,
    owner: 'dskey.example.com.',
    'key tag': 60485,
    algorithm: 5,
    'digest type': 1,
    digest: `( 2BB183AF5F22588179A53B0A 98631FAD1A292118 )`,
    testB: 'dskey.example.com.\t3600\tIN\tDS\t60485\t5\t1\t( 2BB183AF5F22588179A53B0A 98631FAD1A292118 )\n',
    testT: ':dskey.example.com:43:\\354\\105\\005\\001( 2BB183AF5F22588179A53B0A 98631FAD1A292118 ):3600::\n',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    algorithm: 6, // invalid
    msg: /key tag is required/,
  },
]

describe('DS record', function () {
  base.valid(DS, validRecords)
  base.invalid(DS, invalidRecords)

  base.getDescription(DS)
  base.getRFCs(DS, validRecords[0])
  base.getFields(DS, ['key tag', 'algorithm', 'digest type', 'digest'])
  base.getTypeId(DS, 43)

  base.toBind(DS, validRecords)
  base.toTinydns(DS, validRecords)

  base.fromBind(DS, validRecords)
  base.fromTinydns(DS, validRecords)
})
