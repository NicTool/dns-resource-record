
import * as base from './base.js'

import SMIMEA from '../rr/tlsa.js'

const defaults = { class: 'IN', ttl: 3600, type: 'SMIMEA' }

const validRecords = [
  {
    ...defaults,
    owner                         : '_443._tcp.www.example.com.',
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
    ...defaults,
    owner   : 'test.example.com.',
    selector: 6,  // invalid
    msg     : /certificate usage invalid/,
  },
]

describe('SMIMEA record', function () {
  base.valid(SMIMEA, validRecords)
  base.invalid(SMIMEA, invalidRecords)

  base.getDescription(SMIMEA)
  base.getRFCs(SMIMEA, validRecords[0])
  base.getFields(SMIMEA, [ 'certificate usage', 'selector', 'matching type', 'certificate association data' ])
  base.getTypeId(SMIMEA, 52)

  base.toBind(SMIMEA, validRecords)
  // base.toTinydns(SMIMEA, validRecords)

  base.fromBind(SMIMEA, validRecords)
  // base.fromTinydns(SMIMEA, validRecords)
})
