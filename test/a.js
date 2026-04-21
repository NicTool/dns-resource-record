import { describe } from 'node:test'
import A from '../rr/a.js'
import * as base from './base.js'

const defaults = { class: 'IN', ttl: 3600, type: 'A', address: '192.0.2.127' }

const validRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    testB: 'test.example.com.\t3600\tIN\tA\t192.0.2.127\n',
    testT: '+test.example.com:192.0.2.127:3600::\n',
    testW: '0474657374076578616d706c6503636f6d000001000100000e100004c000027f',
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    ttl: 4294967295,
    testB: 'test.example.com.\t4294967295\tIN\tA\t192.0.2.127\n',
    testT: '+test.example.com:192.0.2.127:4294967295::\n',
    testW: '0474657374076578616d706c6503636f6d0000010001ffffffff0004c000027f',
  },
  {
    ...defaults,
    owner: 'a.',
    ttl: 86400,
    testB: 'a.\t86400\tIN\tA\t192.0.2.127\n',
    testT: '+a:192.0.2.127:86400::\n',
    testW: '01610000010001000151800004c000027f',
  },
  {
    ...defaults,
    owner: '*.example.com.',
    testB: '*.example.com.\t3600\tIN\tA\t192.0.2.127\n',
    testT: '+*.example.com:192.0.2.127:3600::\n',
    testW: '012a076578616d706c6503636f6d000001000100000e100004c000027f',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'A',
    address: '192.0.2.1',
    testB: 'nictool.tnpi.net.\t3600\tIN\tA\t192.0.2.1\n',
    testT: '+nictool.tnpi.net:192.0.2.1:3600::\n',
    testW: '076e6963746f6f6c04746e7069036e6574000001000100000e100004c0000201',
  },
  {
    owner: 'www.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'A',
    address: '192.0.2.2',
    testB: 'www.nictool.tnpi.net.\t3600\tIN\tA\t192.0.2.2\n',
    testT: '+www.nictool.tnpi.net:192.0.2.2:3600::\n',
    testW: '03777777076e6963746f6f6c04746e7069036e6574000001000100000e100004c0000202',
  },
  {
    owner: 'mail.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'A',
    address: '192.0.2.3',
    testB: 'mail.nictool.tnpi.net.\t3600\tIN\tA\t192.0.2.3\n',
    testT: '+mail.nictool.tnpi.net:192.0.2.3:3600::\n',
    testW: '046d61696c076e6963746f6f6c04746e7069036e6574000001000100000e100004c0000203',
  },
]

const invalidRecords = [
  { ...defaults, owner: '', msg: /RFC/ },
  { ...defaults, owner: 'something*', msg: /fully/ },
  { ...defaults, owner: 'some*thing', msg: /fully/ },
  { ...defaults, owner: '*something', msg: /fully/ },
  { ...defaults, owner: 'something.*', msg: /fully/ },
  { ...defaults, address: 'hosts.not.valid.here', msg: /address must be IPv4/ },
  { ...defaults, address: '', msg: /address is required/ },
  { ...defaults, address: undefined, msg: /address is required/ },
  { ...defaults, address: '1.x.2.3', msg: /address must be IPv4/ },
  { ...defaults, address: '.1.2.3', msg: /address must be IPv4/ },
  { ...defaults, ttl: '', msg: /TTL must be numeric/ },
  { ...defaults, ttl: -299, msg: /TTL must be a 32-bit integer/ },
  { ...defaults, ttl: 4294967296, msg: /TTL must be a 32-bit integer/ },
]

// merge invalid properties with properties of a valid object
for (let i = 0; i < invalidRecords.length; i++) {
  invalidRecords[i] = { ...validRecords[0], ...invalidRecords[i] }
}

describe('A record', function () {
  base.valid(A, validRecords)
  base.invalid(A, invalidRecords)

  base.getDescription(A)
  base.getRFCs(A, validRecords[0])
  base.getRdataFields(A, ['address'])
  base.getFields(A, ['address'])
  base.getCanonical(A)
  base.getTypeId(A, 1)
  base.getTags(A)

  base.toBind(A, validRecords)
  base.toWire(A, validRecords)
  base.toTinydns(A, validRecords)

  base.fromBind(A, validRecords)
  base.fromTinydns(A, validRecords)
})
