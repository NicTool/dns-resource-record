
const assert = require('assert')

const base = require('./base')

const CERT = require('../rr/cert')

const validRecords = [
  // {
  //   name       : 'mail.example.com.',
  //   ttl        : 86400,
  //   class      : 'IN',
  //   type       : 'CERT',
  //   testB      : '',
  //   testT      : '',
  // },
]

const invalidRecords = [
]

describe('CERT record', function () {
  base.valid(CERT, validRecords)
  base.invalid(CERT, invalidRecords)

  base.getDescription(CERT)
  base.getRFCs(CERT, validRecords[0])
  base.getFields(CERT, [ 'cert type', 'key tag', 'algorithm', 'certificate' ])
  base.getTypeId(CERT, 37)

  base.toBind(CERT, validRecords)
  base.toTinydns(CERT, validRecords)

  base.fromBind(CERT, validRecords)
  base.fromTinydns(CERT, validRecords)
})
