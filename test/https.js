import * as base from './base.js'

import HTTPS from '../rr/https.js'

const defaults = { class: 'IN', ttl: 3600, type: 'HTTPS' }

const validRecords = [
  {
    ...defaults,
    owner: '_8443._foo.api.example.com.',
    ttl: 7200,
    priority: 0,
    'target name': 'svc4.example.net.',
    params: 'alpn="bar" port="8004" ech="..."',
    testB:
      '_8443._foo.api.example.com.\t7200\tIN\tHTTPS\t0\tsvc4.example.net.\talpn="bar" port="8004" ech="..."\n',
  },
  {
    ...defaults,
    owner: '_8080._foo.example.com.',
    priority: 0,
    'target name': 'foosvc.example.net.',
    params: '',
    testB:
      '_8080._foo.example.com.\t3600\tIN\tHTTPS\t0\tfoosvc.example.net.\t\n',
  },
  /*
  _1234._bar.example.com. 300 IN HTTPS 1 svc1.example.net. ( ech="111..." ipv6hint=2001:db8::1 port=1234 )
                                 HTTPS 2 svc2.example.net. ( ech="222..." ipv6hint=2001:db8::2 port=1234 )
*/
]

const invalidRecords = [
  // {
  //   ...defaults,
  //   owner : 'test.example.com.',
  //   'target name': 'not-full-qualified.example.com',
  //   params  : /must be a 16-bit integer/,
  // },
]

describe('HTTPS record', function () {
  base.valid(HTTPS, validRecords)
  base.invalid(HTTPS, invalidRecords)

  base.getDescription(HTTPS)
  base.getRFCs(HTTPS, validRecords[0])
  base.getFields(HTTPS, ['priority', 'target name', 'params'])
  base.getTypeId(HTTPS, 65)

  base.toBind(HTTPS, validRecords)
  // base.toTinydns(HTTPS, validRecords)

  base.fromBind(HTTPS, validRecords)
  // base.fromTinydns(HTTPS, validRecords)
})
