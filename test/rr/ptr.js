import { describe } from 'node:test'

import * as base from '../base.js'

import PTR from '../../rr/ptr.js'

const defaults = { ttl: 86400 }

const valid = [
  {
    ...defaults,
    owner: '2.2.0.192.in-addr.arpa.',
    dname: 'dhcp.example.com.',
    testB: '2.2.0.192.in-addr.arpa.\t86400\tIN\tPTR\tdhcp.example.com.\n',
    testT: '^2.2.0.192.in-addr.arpa:dhcp.example.com:86400::\n',
    testW:
      '0132013201300331393207696e2d61646472046172706100000c00010001518000120464686370076578616d706c6503636f6d00',
  },
]

const invalid = [
  {
    ...defaults,
    owner: 'example.com.',
    dname: '192.0.2.4', // FQDN required
    msg: /dname must be fully qualified/,
  },
]

describe('PTR record', function () {
  base.suite(PTR, { typeId: 12, fields: ['dname'], valid, invalid })
})
