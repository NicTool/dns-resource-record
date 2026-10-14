import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import CERT from '../../rr/cert.js'

const valid = [
  {
    owner: 'mail.example.com.',
    ttl: 86400,
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
    'cert type': 1,
    'key tag': 0,
    algorithm: 0,
    certificate: 'AQIDBA==',
    testB: 'numeric.example.com.\t86400\tIN\tCERT\t1\t0\t0\tAQIDBA==\n',
  },
]

const invalid = [
  ['cert type', undefined, /cert type is required/i],
  ['cert type', 'INVALID', /unknown cert type mnemonic/i],
  ['key tag', 70000, /16-bit integer/i],
  ['algorithm', 300, /8-bit integer/i],
  ['certificate', '', /certificate is required/i],
].map(([f, v, msg]) => ({ ...valid[0], [f]: v, msg }))

describe('CERT record', function () {
  base.suite(CERT, {
    typeId: 37,
    fields: ['cert type', 'key tag', 'algorithm', 'certificate'],
    valid,
    invalid,
  })

  it('getCertTypeValue throws for unknown mnemonic', function () {
    assert.throws(() => new CERT(null).getCertTypeValue('DOESNOTEXIST'), /unknown cert type mnemonic/i)
  })
})
