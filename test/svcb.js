
// import assert from 'assert'

import * as base from './base.js'

import SVCB from '../rr/svcb.js'

const defaults = { class: 'IN', ttl: 3600, type: 'SVCB' }

const validRecords = [
  {
    ...defaults,
    owner        : '_8443._foo.api.example.com.',
    ttl          : 7200,
    priority     : 0,
    'domain name': 'svc4.example.net.',
    'value'      : 'alpn="bar" port="8004" ech="..."',
    testB        : '_8443._foo.api.example.com.\t7200\tIN\tSVCB\t0\tsvc4.example.net.\talpn="bar" port="8004" ech="..."\n',
  },
  {
    ...defaults,
    owner        : '_8080._foo.example.com.',
    priority     : 0,
    'domain name': 'foosvc.example.net.',
    value        : '',
    testB        : '_8080._foo.example.com.\t3600\tIN\tSVCB\t0\tfoosvc.example.net.\t\n',
  },
/*
  _1234._bar.example.com. 300 IN SVCB 1 svc1.example.net. ( ech="111..." ipv6hint=2001:db8::1 port=1234 )
                                 SVCB 2 svc2.example.net. ( ech="222..." ipv6hint=2001:db8::2 port=1234 )
*/
]

const invalidRecords = [
  // {
  //   ...defaults,
  //   owner : 'test.example.com.',
  //   'domain name': 'not-full-qualified.example.com',
  //   value  : /must be a 16-bit integer/,
  // },
]

describe('SVCB record', function () {
  base.valid(SVCB, validRecords)
  base.invalid(SVCB, invalidRecords)

  base.getDescription(SVCB)
  // base.getRFCs(SVCB, validRecords[0])
  base.getFields(SVCB, [ 'priority', 'domain name', 'value' ])
  base.getTypeId(SVCB, 64)

  base.toBind(SVCB, validRecords)
  // base.toTinydns(SVCB, validRecords)

  base.fromBind(SVCB, validRecords)
  // base.fromTinydns(SVCB, validRecords)
})
