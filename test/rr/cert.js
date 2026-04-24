import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import CERT from '../../rr/cert.js'

const defaults = { class: 'IN', ttl: 3600, type: 'CERT' }

const validRecords = [
  {
    owner: 'mail.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'CERT',
    'cert type': 'PGP',
    'key tag': 0,
    algorithm: 0,
    certificate: 'AQIDBA==',
    testB: 'mail.example.com.\t86400\tIN\tCERT\tPGP\t0\t0\tAQIDBA==\n',
    testT: ':mail.example.com:37:\\000\\003\\000\\000\\000\\001\\002\\003\\004:86400::\n',
    testW: '046d61696c076578616d706c6503636f6d0000250001000151800009000300000001020304',
  },
  {
    owner: 'smith.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'CERT',
    'cert type': 'PGP',
    'key tag': 0,
    algorithm: 0,
    certificate: 'BAQICA==',
    testB: 'smith.example.com.\t86400\tIN\tCERT\tPGP\t0\t0\tBAQICA==\n',
    testT: ':smith.example.com:37:\\000\\003\\000\\000\\000\\004\\004\\010\\010:86400::\n',
    testW: '05736d697468076578616d706c6503636f6d0000250001000151800009000300000004040808',
  },
  {
    owner: 'numeric.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'CERT',
    'cert type': 1,
    'key tag': 0,
    algorithm: 0,
    certificate: 'AQIDBA==',
    testB: 'numeric.example.com.\t86400\tIN\tCERT\t1\t0\t0\tAQIDBA==\n',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'mail.example.com.',
    'cert type': undefined,
    'key tag': 0,
    algorithm: 0,
    certificate: 'AQIDBA==',
    msg: /cert type is required/i,
  },
  {
    ...defaults,
    owner: 'mail.example.com.',
    'cert type': 'INVALID', // not a valid mnemonic
    'key tag': 0,
    algorithm: 0,
    certificate: 'hexidecimalkeystring1',
    msg: /unknown cert type mnemonic/i,
  },
  {
    ...defaults,
    owner: 'mail.example.com.',
    'cert type': 'PGP',
    'key tag': 70000, // out of 16-bit range
    algorithm: 0,
    certificate: 'hexidecimalkeystring1',
    msg: /16-bit integer/i,
  },
  {
    ...defaults,
    owner: 'mail.example.com.',
    'cert type': 'PGP',
    'key tag': 0,
    algorithm: 300, // out of 8-bit range
    certificate: 'hexidecimalkeystring1',
    msg: /8-bit integer/i,
  },
  {
    ...defaults,
    owner: 'mail.example.com.',
    'cert type': 'PGP',
    'key tag': 0,
    algorithm: 0,
    certificate: '', // empty certificate
    msg: /certificate is required/i,
  },
]

describe('CERT record', function () {
  base.valid(CERT, validRecords)
  base.invalid(CERT, invalidRecords)

  base.getDescription(CERT)
  base.getRFCs(CERT, validRecords[0])
  base.getFields(CERT, ['cert type', 'key tag', 'algorithm', 'certificate'])
  base.getCanonical(CERT)
  base.getTypeId(CERT, 37)
  base.getTags(CERT)

  base.toBind(CERT, validRecords)
  base.toWire(CERT, validRecords)
  base.toTinydns(CERT, validRecords)

  base.fromBind(CERT, validRecords)
  base.fromTinydns(CERT, validRecords)
  base.fromWire(CERT, validRecords)

  it('getCertTypeValue throws for unknown mnemonic', function () {
    assert.throws(() => new CERT(null).getCertTypeValue('DOESNOTEXIST'), /unknown cert type mnemonic/i)
  })
})
