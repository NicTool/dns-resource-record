import * as base from './base.js'

import NXT from '../rr/nxt.js'

const validRecords = [
  {
    owner: 'big.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'NXT',
    'next domain': 'medium.example.com.',
    'type bit map': 'A SIG NXT',
    testB: `big.example.com.\t86400\tIN\tNXT\tmedium.example.com.\tA SIG NXT\n`,
    // testT        : '\n',
  },
]

const invalidRecords = [
  // {
  // },
]

describe('NXT record', function () {
  base.valid(NXT, validRecords)
  base.invalid(NXT, invalidRecords, { ttl: 3600 })

  base.getDescription(NXT)
  base.getRFCs(NXT, validRecords[0])
  base.getFields(NXT, ['next domain', 'type bit map'])
  base.getTypeId(NXT, 30)

  base.toBind(NXT, validRecords)
  // base.toTinydns(NXT, validRecords)

  base.fromBind(NXT, validRecords)
  // base.fromTinydns(NXT, validRecords)
})
