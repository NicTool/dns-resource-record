import { describe } from 'node:test'
import APL from '../rr/apl.js'
import * as base from './base.js'

const defaults = { class: 'IN', ttl: 3600, type: 'APL' }

const validRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    'apl rdata': '1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::/32',
    testB: 'example.com.\t3600\tIN\tAPL\t1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::/32\n',
    testT:
      ':example.com:42:\\000\\001\\030\\003\\300\\000\\002\\000\\001\\034\\204\\300\\000\\002\\100\\000\\002\\040\\004\\040\\001\\015\\270:3600::\n',
  },
  {
    ...defaults,
    owner: 'host.example.com.',
    ttl: 86400,
    'apl rdata': '1:10.0.0.0/8',
    testB: 'host.example.com.\t86400\tIN\tAPL\t1:10.0.0.0/8\n',
    testT: ':host.example.com:42:\\000\\001\\010\\001\\012:86400::\n',
  },
  {
    ...defaults,
    owner: '*.example.com.',
    ttl: 7200,
    'apl rdata': '2:2001:db8:1::/48',
    testB: '*.example.com.\t7200\tIN\tAPL\t2:2001:db8:1::/48\n',
    testT: ':*.example.com:42:\\000\\002\\060\\006\\040\\001\\015\\270\\000\\001:7200::\n',
  },
  {
    ...defaults,
    owner: 'a.',
    ttl: 2147483647,
    'apl rdata': '1:203.0.113.0/24',
    testB: 'a.\t2147483647\tIN\tAPL\t1:203.0.113.0/24\n',
    testT: ':a:42:\\000\\001\\030\\003\\313\\000\\161:2147483647::\n',
  },
]

const invalidRecords = [
  { ...defaults, owner: '', msg: /RFC/ },
  { ...defaults, owner: 'something*', msg: /fully/ },
  { ...defaults, owner: 'some*thing', msg: /fully/ },
  { ...defaults, owner: '*something', msg: /fully/ },
  { ...defaults, owner: 'something.*', msg: /fully/ },
  { ...defaults, 'apl rdata': '', msg: /apl rdata is required/ },
  { ...defaults, 'apl rdata': undefined, msg: /apl rdata is required/ },
  { ...defaults, type: '', msg: /type is required/ },
  { ...defaults, type: undefined, msg: /type is required/ },
  { ...defaults, ttl: '', msg: /TTL must be numeric/ },
  { ...defaults, ttl: -299, msg: /TTL must be a 32-bit integer/ },
  { ...defaults, ttl: 2147483648, msg: /TTL must be a 32-bit integer/ },
]

for (let i = 0; i < invalidRecords.length; i++) {
  invalidRecords[i] = { ...validRecords[0], ...invalidRecords[i] }
}

describe('APL record', function () {
  base.valid(APL, validRecords)
  base.invalid(APL, invalidRecords)

  base.getDescription(APL)
  base.getRFCs(APL, validRecords[0])
  base.getRdataFields(APL, ['apl rdata'])
  base.getFields(APL, ['apl rdata'])
  base.getTypeId(APL, 42)

  base.toBind(APL, validRecords)
  base.toTinydns(APL, validRecords)

  base.fromBind(APL, validRecords)
  base.fromTinydns(APL, validRecords)
})
