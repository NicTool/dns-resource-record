import * as base from './base.js'

import NSEC from '../rr/nsec.js'

const validRecords = [
  {
    owner: 'alfa.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'NSEC',
    'next domain': 'host.example.com.',
    'type bit maps': 'A MX RRSIG NSEC TYPE1234',
    testB: `alfa.example.com.\t86400\tIN\tNSEC\thost.example.com.\tA MX RRSIG NSEC TYPE1234\n`,
    // testT        : '\n',
  },
]

const invalidRecords = [
  // {
  // },
]

describe('NSEC record', function () {
  base.valid(NSEC, validRecords)
  base.invalid(NSEC, invalidRecords, { ttl: 3600 })

  base.getDescription(NSEC)
  base.getRFCs(NSEC, validRecords[0])
  base.getFields(NSEC, ['next domain', 'type bit maps'])
  base.getTypeId(NSEC, 47)

  base.toBind(NSEC, validRecords)
  // base.toTinydns(NSEC, validRecords)

  base.fromBind(NSEC, validRecords)
  // base.fromTinydns(NSEC, validRecords)
})
