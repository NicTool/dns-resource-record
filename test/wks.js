import * as base from './base.js'

import WKS from '../rr/wks.js'

const defaults = { class: 'IN', ttl: 3600, type: 'WKS' }

const validRecords = [
  {
    ...defaults,
    owner: 'host.example.com.',
    address: '192.0.2.1',
    protocol: 'TCP',
    'bit map': 'ftp smtp',
    testB: 'host.example.com.\t3600\tIN\tWKS\t192.0.2.1\tTCP\tftp smtp\n',
  },
  {
    ...defaults,
    owner: 'host.example.com.',
    address: '192.0.2.2',
    protocol: 'UDP',
    'bit map': 'domain',
    testB: 'host.example.com.\t3600\tIN\tWKS\t192.0.2.2\tUDP\tdomain\n',
  },
  {
    ...defaults,
    owner: 'host.example.com.',
    address: '192.0.2.3',
    protocol: 'TCP',
    'bit map': '',
    testB: 'host.example.com.\t3600\tIN\tWKS\t192.0.2.3\tTCP\t\n',
  },
]

const invalidRecords = [
  { ...defaults, owner: 'host.example.com.', address: '', protocol: 'TCP', 'bit map': '', msg: /address is required/ },
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
  base.getTypeId(WKS, 11)

  base.toBind(WKS, validRecords)

  base.fromBind(WKS, validRecords)
})
