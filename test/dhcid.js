import * as base from './base.js'

import DHCID from '../rr/dhcid.js'

const validRecords = [
  {
    owner: 'host.example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'DHCID',
    data: 'AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=',
    testB: 'host.example.com.\t3600\tIN\tDHCID\tAAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=\n',
  },
]

const invalidRecords = [
  {
    owner: 'host.example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'DHCID',
    data: '',
    msg: /data is required/,
  },
]

describe('DHCID record', function () {
  base.valid(DHCID, validRecords)
  base.invalid(DHCID, invalidRecords)

  base.getDescription(DHCID)
  base.getRFCs(DHCID, validRecords[0])
  base.getFields(DHCID, ['data'])
  base.getTypeId(DHCID, 49)

  base.toBind(DHCID, validRecords)

  base.fromBind(DHCID, validRecords)
})
