import { describe } from 'node:test'
import * as base from '../base.js'

import NSEC from '../../rr/nsec.js'

const validRecords = [
  {
    owner: 'alfa.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'NSEC',
    'next domain': 'host.example.com.',
    'type bit maps': 'A MX RRSIG NSEC TYPE1234',
    testB: `alfa.example.com.\t86400\tIN\tNSEC\thost.example.com.\tA MX RRSIG NSEC TYPE1234\n`,
    testT: ':alfa.example.com:47:\\004host\\007example\\003com\\000A MX RRSIG NSEC TYPE1234:86400::\n',
    testW:
      '04616c6661076578616d706c6503636f6d00002f000100015180003704686f7374076578616d706c6503636f6d000006400100000003041b000000000000000000000000000000000000000000000000000020',
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
  base.getCanonical(NSEC)
  base.getTypeId(NSEC, 47)
  base.getTags(NSEC)

  base.toBind(NSEC, validRecords)
  base.toWire(NSEC, validRecords)
  base.toTinydns(NSEC, validRecords)

  base.fromBind(NSEC, validRecords)
  base.fromTinydns(NSEC, validRecords)
  base.fromWire(NSEC, validRecords)
})
