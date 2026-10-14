import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import WKS from '../../rr/wks.js'

const valid = [
  {
    owner: 'host.example.com.',
    address: '192.0.2.1',
    protocol: 'TCP',
    'bit map': 'ftp smtp',
    testB: 'host.example.com.\t3600\tIN\tWKS\t192.0.2.1\tTCP\tftp smtp\n',
    testT: ':host.example.com:11:\\300\\000\\002\\001\\006\\000\\000\\004@:3600::\n',
    testW: '04686f7374076578616d706c6503636f6d00000b000100000e100009c00002010600000440',
  },
  {
    owner: 'host.example.com.',
    address: '192.0.2.2',
    protocol: 'UDP',
    'bit map': 'domain',
    testB: 'host.example.com.\t3600\tIN\tWKS\t192.0.2.2\tUDP\tdomain\n',
    testT: ':host.example.com:11:\\300\\000\\002\\002\\021\\000\\000\\000\\000\\000\\000\\004:3600::\n',
    testW: '04686f7374076578616d706c6503636f6d00000b000100000e10000cc00002021100000000000004',
  },
  {
    owner: 'host.example.com.',
    address: '192.0.2.3',
    protocol: 'TCP',
    'bit map': '',
    testB: 'host.example.com.\t3600\tIN\tWKS\t192.0.2.3\tTCP\n',
    testT: ':host.example.com:11:\\300\\000\\002\\003\\006:3600::\n',
    testW: '04686f7374076578616d706c6503636f6d00000b000100000e100005c000020306',
  },
]

const invalid = [
  {
    owner: 'host.example.com.',
    address: '',
    protocol: 'TCP',
    'bit map': '',
    msg: /address must be a valid IPv4 address/,
  },
  {
    owner: 'host.example.com.',
    address: 'not-an-ip',
    protocol: 'TCP',
    'bit map': '',
    msg: /address must be a valid IPv4 address/,
  },
  {
    owner: 'host.example.com.',
    address: '192.0.2.1',
    protocol: 'SCTP',
    'bit map': '',
    msg: /protocol must be TCP or UDP/,
  },
  ...['-1', '70000', 'nosuchservice'].map((entry) => ({
    owner: 'h.example.',
    address: '192.0.2.1',
    protocol: 'TCP',
    'bit map': `ftp ${entry}`,
    msg: /known service or a port 0-65535/,
  })),
]

describe('WKS record', function () {
  base.suite(WKS, {
    typeId: 11,
    fields: ['address', 'protocol', 'bit map'],
    valid,
    invalid,
  })

  const wks = (opts) =>
    new WKS({
      owner: 'h.example.',
      ttl: 60,
      address: '192.0.2.1',
      protocol: 'TCP',
      'bit map': 'smtp',
      ...opts,
    })

  it('exports MaraDNS csv2 as IP, protocol number and port list', function () {
    assert.equal(wks({ 'bit map': 'ftp smtp' }).toMaraDNS(), 'h.example.\t+60\tWKS\t192.0.2.1 6 21,25 ~\n')
    assert.match(wks({ 'bit map': '8080' }).toMaraDNS(), /\tRAW 11\t/, 'csv2 WKS ports stop at 1023')
    assert.match(wks({ 'bit map': '' }).toMaraDNS(), /\tRAW 11\t/)
  })

  it('stores the protocol as TCP or UDP from a name or a number', function () {
    assert.equal(wks({ 'bit map': 'ftp 65535' }).get('bit map'), 'ftp 65535')
    for (const protocol of ['tcp', 'TCP', 6, '6']) {
      assert.equal(wks({ protocol }).get('protocol'), 'TCP')
      assert.equal(WKS.fromWire(wks({ protocol }).toWire()).get('protocol'), 'TCP')
    }
  })
})
