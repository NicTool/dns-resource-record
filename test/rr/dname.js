import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import DNAME from '../../rr/dname.js'

const defaults = { ttl: 86400 }

const valid = [
  {
    ...defaults,
    owner: '_tcp.example.com.',
    target: '_tcp.example.net.',
    testB: '_tcp.example.com.\t86400\tIN\tDNAME\t_tcp.example.net.\n',
    testT: ':_tcp.example.com:39:\\004_tcp\\007example\\003net\\000:86400::\n',
  },
  {
    owner: 'old.nictool.tnpi.net.',
    target: 'new.tnpi.net.',
    testB: 'old.nictool.tnpi.net.\t3600\tIN\tDNAME\tnew.tnpi.net.\n',
    testT: ':old.nictool.tnpi.net:39:\\003new\\004tnpi\\003net\\000:3600::\n',
    testW: '036f6c64076e6963746f6f6c04746e7069036e6574000027000100000e10000e036e657704746e7069036e657400',
  },
]

const invalid = [
  {
    ...defaults,
    owner: 'spf.example.com.',
    target: '1.2.3.4', // FQDN required
    msg: /target must be a domain name/,
  },
]

describe('DNAME record', function () {
  base.suite(DNAME, { typeId: 39, fields: ['target'], valid, invalid })

  it('toMaraDNS throws: MaraDNS refuses DNAME, even as RAW', function () {
    assert.throws(() => new DNAME(valid[0]).toMaraDNS(), /MaraDNS does not support DNAME/)
  })
})
