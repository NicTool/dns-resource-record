import * as base from './base.js'

import RP from '../rr/rp.js'

const validRecords = [
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'RP',
    mbox: 'admin.example.com.',
    txt: 'info.example.com.',
    testB: 'example.com.\t3600\tIN\tRP\tadmin.example.com.\tinfo.example.com.\n',
  },
  {
    owner: 'host.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'RP',
    mbox: 'hostmaster.example.com.',
    txt: '.',
    testB: 'host.example.com.\t86400\tIN\tRP\thostmaster.example.com.\t.\n',
  },
]

const invalidRecords = [
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'RP',
    mbox: '',
    txt: 'info.example.com.',
    msg: /mbox is required/,
  },
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'RP',
    mbox: 'admin.example.com.',
    txt: '',
    msg: /txt is required/,
  },
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'RP',
    mbox: 'admin.example.com',
    txt: 'info.example.com.',
    msg: /mbox must be fully qualified/,
  },
]

describe('RP record', function () {
  base.valid(RP, validRecords)
  base.invalid(RP, invalidRecords)

  base.getDescription(RP)
  base.getRFCs(RP, validRecords[0])
  base.getFields(RP, ['mbox', 'txt'])
  base.getTypeId(RP, 17)

  base.toBind(RP, validRecords)

  base.fromBind(RP, validRecords)
})
