import { describe } from 'node:test'

import * as base from '../base.js'

import NS from '../../rr/ns.js'

const valid = [
  {
    owner: 'example.com.',
    dname: 'ns1.example.com.',
    testB: 'example.com.\t3600\tIN\tNS\tns1.example.com.\n',
    testT: '&example.com::ns1.example.com:3600::\n',
    testW: '076578616d706c6503636f6d000002000100000e100011036e7331076578616d706c6503636f6d00',
  },
  {
    owner: 'nictool.tnpi.net.',
    dname: 'ns1.tnpi.net.',
    testB: 'nictool.tnpi.net.\t3600\tIN\tNS\tns1.tnpi.net.\n',
    testT: '&nictool.tnpi.net::ns1.tnpi.net:3600::\n',
    testW: '076e6963746f6f6c04746e7069036e6574000002000100000e10000e036e733104746e7069036e657400',
  },
  {
    owner: 'nictool.tnpi.net.',
    dname: 'ns2.tnpi.net.',
    testB: 'nictool.tnpi.net.\t3600\tIN\tNS\tns2.tnpi.net.\n',
    testT: '&nictool.tnpi.net::ns2.tnpi.net:3600::\n',
    testW: '076e6963746f6f6c04746e7069036e6574000002000100000e10000e036e733204746e7069036e657400',
  },
]

const invalid = [
  {
    owner: 'example.com.',
    dname: '1.2.3.4', // FQDN required
    msg: /dname must be fully qualified/,
  },
]

describe('NS record', function () {
  base.suite(NS, { typeId: 2, fields: ['dname'], valid, invalid })
})
