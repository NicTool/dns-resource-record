import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import SOA from '../../rr/soa.js'

const valid = [
  {
    owner: 'example.com.',
    mname: 'ns1.example.com.',
    rname: 'matt.example.com.',
    serial: 1,
    refresh: 7200,
    retry: 3600,
    expire: 1209600,
    minimum: 3600,
    testB: `example.com.\t3600\tIN\tSOA\tns1.example.com.\tmatt.example.com.\t1\t7200\t3600\t1209600\t3600\n`,
    testT: 'Zexample.com:ns1.example.com:matt.example.com:1:7200:3600:1209600:3600:3600::\n',
    testW:
      '076578616d706c6503636f6d000006000100000e100037036e7331076578616d706c6503636f6d00046d617474076578616d706c6503636f6d000000000100001c2000000e100012750000000e10',
  },
  {
    owner: '2.example.com.',
    mname: 'ns2.example.com.',
    rname: 'matt.example.com.',
    serial: 1,
    refresh: 7200,
    retry: 3600,
    expire: 1209600,
    minimum: 3600,
    testB: `2.example.com.\t3600\tIN\tSOA\tns2.example.com.\tmatt.example.com.\t1\t7200\t3600\t1209600\t3600\n`,
    testT: 'Z2.example.com:ns2.example.com:matt.example.com:1:7200:3600:1209600:3600:3600::\n',
    testW:
      '0132076578616d706c6503636f6d000006000100000e100037036e7332076578616d706c6503636f6d00046d617474076578616d706c6503636f6d000000000100001c2000000e100012750000000e10',
  },
]

const invalid = [
  {
    owner: 'example.com.',
    mname: 'ns1.example.com.',
    rname: 'matt.example.com.',
    serial: 4294967296,
    refresh: 7200,
    retry: 3600,
    expire: 1209600,
    msg: /serial must be a 32-bit integer/,
  },
]

describe('SOA record', function () {
  base.suite(SOA, {
    typeId: 6,
    fields: ['mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum'],
    valid,
    invalid,
  })

  it('exports MaraDNS, keeping the TTL', function () {
    assert.equal(
      new SOA({ ...valid[0], ttl: 3600 }).toMaraDNS(),
      'example.com.\t+3600\tSOA\tns1.example.com.\tmatt.example.com.\t1\t7200\t3600\t1209600\t3600 ~\n',
    )
  })
})
