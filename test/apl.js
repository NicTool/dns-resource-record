import * as base from './base.js'

import APL from '../rr/apl.js'

const validRecords = [
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'APL',
    'apl rdata': '1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::/32',
    testB: 'example.com.\t3600\tIN\tAPL\t1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::/32\n',
    testT:
      ':example.com:42:\\000\\001\\030\\003\\300\\000\\002\\000\\001\\034\\204\\300\\000\\002\\100\\000\\002\\040\\004\\040\\001\\015\\270:3600::\n',
  },
  {
    owner: 'host.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'APL',
    'apl rdata': '1:10.0.0.0/8',
    testB: 'host.example.com.\t86400\tIN\tAPL\t1:10.0.0.0/8\n',
    testT: ':host.example.com:42:\\000\\001\\010\\001\\012:86400::\n',
  },
]

const invalidRecords = [
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'APL',
    'apl rdata': '',
    msg: /apl rdata is required/,
  },
]

describe('APL record', function () {
  base.valid(APL, validRecords)
  base.invalid(APL, invalidRecords)

  base.getDescription(APL)
  base.getRFCs(APL, validRecords[0])
  base.getFields(APL, ['apl rdata'])
  base.getTypeId(APL, 42)

  base.toBind(APL, validRecords)
  base.toTinydns(APL, validRecords)

  base.fromBind(APL, validRecords)
})
