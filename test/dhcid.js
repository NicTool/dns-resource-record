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
    testT:
      ':host.example.com:49:\\000\\002\\001co\\300\\270\\047\\034\\202\\202\\133\\261\\254\\134A\\317SQ\\252i\\264\\376\\275\\224\\350\\361\\174\\333\\225\\000\\015\\244\\214\\100:3600::\n',
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
  base.toTinydns(DHCID, validRecords)

  base.fromBind(DHCID, validRecords)
})
