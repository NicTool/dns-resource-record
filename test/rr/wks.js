import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import WKS from '../../rr/wks.js'

const defaults = { class: 'IN', ttl: 3600, type: 'WKS' }

const validRecords = [
  {
    ...defaults,
    owner: 'host.example.com.',
    address: '192.0.2.1',
    protocol: 'TCP',
    'bit map': 'ftp smtp',
    testB: 'host.example.com.\t3600\tIN\tWKS\t192.0.2.1\tTCP\tftp smtp\n',
    testT: ':host.example.com:11:\\300\\000\\002\\001\\006\\000\\000\\004@:3600::\n',
    testW: '04686f7374076578616d706c6503636f6d00000b000100000e100009c00002010600000440',
  },
  {
    ...defaults,
    owner: 'host.example.com.',
    address: '192.0.2.2',
    protocol: 'UDP',
    'bit map': 'domain',
    testB: 'host.example.com.\t3600\tIN\tWKS\t192.0.2.2\tUDP\tdomain\n',
    testT: ':host.example.com:11:\\300\\000\\002\\002\\021\\000\\000\\000\\000\\000\\000\\004:3600::\n',
    testW: '04686f7374076578616d706c6503636f6d00000b000100000e10000cc00002021100000000000004',
  },
  {
    ...defaults,
    owner: 'host.example.com.',
    address: '192.0.2.3',
    protocol: 'TCP',
    'bit map': '',
    testB: 'host.example.com.\t3600\tIN\tWKS\t192.0.2.3\tTCP\t\n',
    testT: ':host.example.com:11:\\300\\000\\002\\003\\006:3600::\n',
    testW: '04686f7374076578616d706c6503636f6d00000b000100000e100005c000020306',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'host.example.com.',
    address: '',
    protocol: 'TCP',
    'bit map': '',
    msg: /address is required/,
  },
  {
    ...defaults,
    owner: 'host.example.com.',
    address: 'not-an-ip',
    protocol: 'TCP',
    'bit map': '',
    msg: /address must be IPv4/,
  },
  {
    ...defaults,
    owner: 'host.example.com.',
    address: '192.0.2.1',
    protocol: 'SCTP',
    'bit map': '',
    msg: /protocol must be TCP or UDP/,
  },
]

describe('WKS record', function () {
  base.valid(WKS, validRecords)
  base.invalid(WKS, invalidRecords)

  base.getDescription(WKS)
  base.getRFCs(WKS, validRecords[0])
  base.getFields(WKS, ['address', 'protocol', 'bit map'])
  base.getCanonical(WKS)
  base.getTypeId(WKS, 11)
  base.getTags(WKS)

  base.toBind(WKS, validRecords)
  base.toWire(WKS, validRecords)
  base.toTinydns(WKS, validRecords)

  base.fromBind(WKS, validRecords)
  base.fromTinydns(WKS, validRecords)
  base.fromWire(WKS, validRecords)

  it('exports MaraDNS csv2 as IP, protocol number and port list', function () {
    const wks = (bitMap) =>
      new WKS({
        owner: 'h.example.',
        ttl: 60,
        type: 'WKS',
        address: '192.0.2.1',
        protocol: 'TCP',
        'bit map': bitMap,
      })
    assert.equal(wks('ftp smtp').toMaraDNS(), 'h.example.\t+60\tWKS\t192.0.2.1 6 21,25 ~\n')
    assert.match(wks('8080').toMaraDNS(), /\tRAW 11\t/, 'csv2 WKS ports stop at 1023')
    assert.match(wks('').toMaraDNS(), /\tRAW 11\t/)
  })

  it('rejects a bit map entry that is not a known service or a 16-bit port', function () {
    const wks = (bitMap) =>
      new WKS({
        owner: 'h.example.',
        ttl: 60,
        type: 'WKS',
        address: '192.0.2.1',
        protocol: 'TCP',
        'bit map': bitMap,
      })
    for (const entry of ['-1', '70000', 'nosuchservice'])
      assert.throws(() => wks(`ftp ${entry}`), /known service or a port 0-65535/, entry)
    assert.equal(wks('ftp 65535').get('bit map'), 'ftp 65535')
  })
})
