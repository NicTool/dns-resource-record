
// const assert = require('assert')

const base = require('./base')

const SMIMEA = require('../rr/tlsa')

const validRecords = [
  {
    class                         : 'IN',
    owner                         : '_443._tcp.www.example.com.',
    type                          : 'SMIMEA',
    ttl                           : 3600,
    'certificate usage'           : 0,
    selector                      : 0,
    'matching type'               : 1,
    'certificate association data': '( d2abde240d7cd3ee6b4b28c54df034b9 7983a1d16e8a410e4561cb106618e971 )',
    testB                         : '_443._tcp.www.example.com.\t3600\tIN\tSMIMEA\t0\t0\t1\t( d2abde240d7cd3ee6b4b28c54df034b9 7983a1d16e8a410e4561cb106618e971 )\n',
    // testT                      : '',
  },
]

const invalidRecords = [
  {
    // owner    : 'test.example.com',
    selector: 6,  // invalid
  },
]

describe('SMIMEA record', function () {
  base.valid(SMIMEA, validRecords, { ttl: 3600 })
  base.invalid(SMIMEA, invalidRecords, { ttl: 3600 })

  base.getDescription(SMIMEA)
  base.getRFCs(SMIMEA, validRecords[0])
  base.getFields(SMIMEA, [ 'certificate usage', 'selector', 'matching type', 'certificate association data' ])
  base.getTypeId(SMIMEA, 52)

  base.toBind(SMIMEA, validRecords)
  // base.toTinydns(SMIMEA, validRecords)

  base.fromBind(SMIMEA, validRecords)
  // base.fromTinydns(SMIMEA, validRecords)
})
