import { describe } from 'node:test'
import A from '../../rr/a.js'
import * as base from '../base.js'

const defaults = { address: '192.0.2.127' }

const valid = [
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
    ttl: 2147483647,
    testB: 'test.example.com.\t2147483647\tIN\tA\t192.0.2.127\n',
    testT: '+test.example.com:192.0.2.127:2147483647::\n',
    testW: '0474657374076578616d706c6503636f6d00000100017fffffff0004c000027f',
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
    address: '192.0.2.1',
    testB: 'nictool.tnpi.net.\t3600\tIN\tA\t192.0.2.1\n',
    testT: '+nictool.tnpi.net:192.0.2.1:3600::\n',
    testW: '076e6963746f6f6c04746e7069036e6574000001000100000e100004c0000201',
  },
  {
    owner: 'www.nictool.tnpi.net.',
    address: '192.0.2.2',
    testB: 'www.nictool.tnpi.net.\t3600\tIN\tA\t192.0.2.2\n',
    testT: '+www.nictool.tnpi.net:192.0.2.2:3600::\n',
    testW: '03777777076e6963746f6f6c04746e7069036e6574000001000100000e100004c0000202',
  },
  {
    owner: 'mail.nictool.tnpi.net.',
    address: '192.0.2.3',
    testB: 'mail.nictool.tnpi.net.\t3600\tIN\tA\t192.0.2.3\n',
    testT: '+mail.nictool.tnpi.net:192.0.2.3:3600::\n',
    testW: '046d61696c076e6963746f6f6c04746e7069036e6574000001000100000e100004c0000203',
  },
]

const invalid = [
  { owner: '', msg: /RFC/ },
  { owner: 'something*', msg: /fully/ },
  { owner: 'some*thing', msg: /fully/ },
  { owner: '*something', msg: /fully/ },
  { owner: 'something.*', msg: /fully/ },
  { address: 'hosts.not.valid.here', msg: /address must be IPv4/ },
  { address: '', msg: /address is required/ },
  { address: undefined, msg: /address is required/ },
  { address: '1.x.2.3', msg: /address must be IPv4/ },
  { address: '.1.2.3', msg: /address must be IPv4/ },
  { ttl: '', msg: /TTL must be numeric/ },
  { ttl: -299, msg: /TTL must be an integer from 0 to 2147483647/ },
  { ttl: 2147483648, msg: /TTL must be an integer from 0 to 2147483647/ },
  { type: 'NONEXIST', msg: /type NONEXIST doesn't match A/ },
].map((inv) => ({ ...valid[0], ...inv }))

describe('A record', function () {
  base.suite(A, { typeId: 1, fields: ['address'], valid, invalid })
})
