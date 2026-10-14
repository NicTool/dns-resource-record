import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import MX from '../../rr/mx.js'

const defaults = { preference: 0 }

const valid = [
  {
    ...defaults,
    owner: 'test.example.com.',
    preference: 0,
    exchange: 'mail.example.com.',
    testB: 'test.example.com.\t3600\tIN\tMX\t0\tmail.example.com.\n',
    testT: '@test.example.com::mail.example.com:0:3600::\n',
    testW: '0474657374076578616d706c6503636f6d00000f000100000e1000140000046d61696c076578616d706c6503636f6d00',
  },
  {
    ...defaults,
    owner: 'www.example.com.',
    ttl: 86400,
    preference: 0,
    exchange: '.', // null MX, RFC 7505
    testB: 'www.example.com.\t86400\tIN\tMX\t0\t.\n',
    testT: '@www.example.com::.:0:86400::\n',
    testW: '03777777076578616d706c6503636f6d00000f0001000151800003000000',
  },
  {
    owner: 'nictool.tnpi.net.',
    preference: 10,
    exchange: 'mail.nictool.tnpi.net.',
    testB: 'nictool.tnpi.net.\t3600\tIN\tMX\t10\tmail.nictool.tnpi.net.\n',
    testT: '@nictool.tnpi.net::mail.nictool.tnpi.net:10:3600::\n',
    testW:
      '076e6963746f6f6c04746e7069036e657400000f000100000e100019000a046d61696c076e6963746f6f6c04746e7069036e657400',
  },
  {
    owner: 'nictool.tnpi.net.',
    preference: 20,
    exchange: 'mail.tnpi.net.',
    testB: 'nictool.tnpi.net.\t3600\tIN\tMX\t20\tmail.tnpi.net.\n',
    testT: '@nictool.tnpi.net::mail.tnpi.net:20:3600::\n',
    testW: '076e6963746f6f6c04746e7069036e657400000f000100000e1000110014046d61696c04746e7069036e657400',
  },
]

const invalid = [
  {
    ...defaults,
    owner: 'test.example.com.',
    exchange: 'not-full-qualified.example.com',
    msg: /exchange must be fully qualified/,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    exchange: '192.0.2.1',
    msg: /exchange must be a domain name/,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    exchange: '-blah',
    msg: /exchange must be fully qualified/,
  },
]

describe('MX record', function () {
  base.suite(MX, {
    typeId: 15,
    fields: ['preference', 'exchange'],
    valid,
    invalid,
  })

  it('exports a null MX (RFC 7505) to MaraDNS as RAW, since csv2 cannot name the root', function () {
    const mx = new MX({ owner: 'a.example.', ttl: 60, preference: 0, exchange: '.' })
    assert.equal(mx.toMaraDNS(), 'a.example.\t+60\tRAW 15\t\\x00\\x00\\x00 ~\n')
  })

  it('rejects wire rdata too short for its fixed fields', function () {
    assert.throws(
      () => new MX(null).fromWire({ owner: 'a.example.', cls: 'IN', ttl: 60, rdata: Uint8Array.from([0]) }),
      /MX: rdata is truncated/,
    )
  })
})
