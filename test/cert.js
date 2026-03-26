import { describe } from 'node:test'
import * as base from './base.js'

import CERT from '../rr/cert.js'

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
    certificate: 'hexidecimalkeystring1',
    testB: 'mail.example.com.\t86400\tIN\tCERT\tPGP\t0\t0\thexidecimalkeystring1\n',
    testT: ':mail.example.com:37:\\000\\003\\000\\000\\000hexidecimalkeystring1:86400::\n',
  },
  {
    owner: 'smith.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'CERT',
    'cert type': 'PGP',
    'key tag': 0,
    algorithm: 0,
    certificate: 'hexidecimalkeystring2',
    testB: 'smith.example.com.\t86400\tIN\tCERT\tPGP\t0\t0\thexidecimalkeystring2\n',
    testT: ':smith.example.com:37:\\000\\003\\000\\000\\000hexidecimalkeystring2:86400::\n',
  },
]

const invalidRecords = [
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

  base.toBind(CERT, validRecords)
  base.toWire(CERT, validRecords)
  base.toTinydns(CERT, validRecords)

  base.fromBind(CERT, validRecords)
  base.fromTinydns(CERT, validRecords)
})
