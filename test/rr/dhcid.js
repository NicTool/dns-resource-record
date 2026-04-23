import { describe } from 'node:test'
import * as base from '../base.js'

import DHCID from '../../rr/dhcid.js'

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
  {
    owner: 'dhcid.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'DHCID',
    data: 'AAIBxwkxGO0Jou7NMsGBAAAAAAAAAAAA',
    testB: 'dhcid.nictool.tnpi.net.\t3600\tIN\tDHCID\tAAIBxwkxGO0Jou7NMsGBAAAAAAAAAAAA\n',
    testT:
      ':dhcid.nictool.tnpi.net:49:\\000\\002\\001\\307\\0111\\030\\355\\011\\242\\356\\3152\\301\\201\\000\\000\\000\\000\\000\\000\\000\\000\\000:3600::\n',
    testW:
      '056468636964076e6963746f6f6c04746e7069036e6574000031000100000e100018000201c7093118ed09a2eecd32c181000000000000000000',
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
  base.getCanonical(DHCID)
  base.getTypeId(DHCID, 49)
  base.getTags(DHCID)

  base.toBind(DHCID, validRecords)
  base.toWire(DHCID, validRecords)
  base.toTinydns(DHCID, validRecords)

  base.fromBind(DHCID, validRecords)
  base.fromTinydns(DHCID, validRecords)
})

base.fromWire(DHCID, validRecords)
