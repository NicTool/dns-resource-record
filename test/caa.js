import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import * as base from './base.js'
import CAA from '../rr/caa.js'

const defaults = { class: 'IN', ttl: 3600, type: 'CAA' }

const validRecords = [
  {
    owner: 'ns1.example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'CAA',
    flags: 0,
    tag: 'issue',
    value: 'http://letsencrypt.org',
    testB: 'ns1.example.com.\t3600\tIN\tCAA\t0\tissue\t"http://letsencrypt.org"\n',
    testT: ':ns1.example.com:257:\\000\\005issuehttp\\072\\057\\057letsencrypt.org:3600::\n',
    testW:
      '036e7331076578616d706c6503636f6d000101000100000e10001d00056973737565687474703a2f2f6c657473656e63727970742e6f7267',
  },
  {
    owner: 'ns2.example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'CAA',
    flags: 0,
    tag: 'issue',
    value: 'mailto:lets-crypt.org',
    testB: 'ns2.example.com.\t3600\tIN\tCAA\t0\tissue\t"mailto:lets-crypt.org"\n',
    testT: ':ns2.example.com:257:\\000\\005issuemailto\\072lets-crypt.org:3600::\n',
    testW:
      '036e7332076578616d706c6503636f6d000101000100000e10001c000569737375656d61696c746f3a6c6574732d63727970742e6f7267',
  },
  {
    owner: 'example.net.',
    ttl: 86400,
    type: 'CAA',
    flags: 0,
    tag: 'issuewild',
    value: 'https://letsencrypt.org',
    testB: 'example.net.\t86400\tIN\tCAA\t0\tissuewild\t"https://letsencrypt.org"\n',
    testT: ':example.net:257:\\000\\011issuewildhttps\\072\\057\\057letsencrypt.org:86400::\n',
    testW:
      '076578616d706c65036e657400010100010001518000220009697373756577696c6468747470733a2f2f6c657473656e63727970742e6f7267',
  },
  {
    owner: 'certs.example.com.',
    ttl: 86400,
    type: 'CAA',
    flags: 0,
    tag: 'issue',
    value: 'ca1.example.net',
    testB: 'certs.example.com.\t86400\tIN\tCAA\t0\tissue\t"ca1.example.net"\n',
    testT: ':certs.example.com:257:\\000\\005issueca1.example.net:86400::\n',
    testW:
      '056365727473076578616d706c6503636f6d0001010001000151800016000569737375656361312e6578616d706c652e6e6574',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'CAA',
    flags: 0,
    tag: 'issue',
    value: 'letsencrypt.org',
    testW:
      '076e6963746f6f6c04746e7069036e6574000101000100000e100016000569737375656c657473656e63727970742e6f7267',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'CAA',
    flags: 0,
    tag: 'issuewild',
    value: 'letsencrypt.org',
    testW:
      '076e6963746f6f6c04746e7069036e6574000101000100000e10001a0009697373756577696c646c657473656e63727970742e6f7267',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'CAA',
    flags: 0,
    tag: 'iodef',
    value: 'mailto:hostmaster@tnpi.net',
    testW:
      '076e6963746f6f6c04746e7069036e6574000101000100000e1000210005696f6465666d61696c746f3a686f73746d617374657240746e70692e6e6574',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    flags: 128,
    tag: 'iodef',
    value: 'letsencrypt.org', // missing iodef prefix
    msg: /prefix/,
  },
  {
    ...defaults,
    owner: 'example.com.',
    flags: 128,
    tag: 'invalid', // invalid
    value: 'http://letsencrypt.org',
    msg: /not recognized/,
  },
  {
    ...defaults,
    owner: 'example.com.',
    flags: 15, // invalid
    tag: 'issue',
    value: 'http://letsencrypt.org',
    msg: /not recognized/,
  },
]

describe('CAA record', function () {
  base.valid(CAA, validRecords)
  base.invalid(CAA, invalidRecords)

  base.getDescription(CAA)
  base.getRFCs(CAA, validRecords[0])
  base.getFields(CAA, ['flags', 'tag', 'value'])
  base.getCanonical(CAA)
  base.getTypeId(CAA, 257)
  base.getTags(CAA)

  base.toBind(CAA, validRecords)
  base.toWire(CAA, validRecords)
  base.toTinydns(CAA, validRecords)

  base.fromBind(CAA, validRecords)
  base.fromTinydns(CAA, validRecords)

  it('defaults type to CAA when omitted from constructor', function () {
    const r = new CAA({
      owner: 'example.com.',
      ttl: 3600,
      flags: 0,
      tag: 'issue',
      value: 'http://letsencrypt.org',
    })
    assert.equal(r.get('type'), 'CAA')
  })
})
