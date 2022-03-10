
// const assert = require('assert')

const base = require('./base')

const NAPTR = require('../rr/naptr')

const validRecords = [
  {
    class      : 'IN',
    name       : 'cid.urn.arpa',
    type       : 'NAPTR',
    order      : 100,
    preference : 10,
    flags      : '',
    service    : '',
    regexp     : '!^urn:cid:.+@([^\\.]+\\.)(.*)$!\2!i',
    replacement: '.',
    ttl        : 86400,
    testB      : 'cid.urn.arpa\t86400\tIN\tNAPTR\t100\t10\t""\t""\t"!^urn:cid:.+@([^\\.]+\\.)(.*)$!\x02!i"\t.\n',
    testT      : ':cid.urn.arpa:35:\\000\\144\\000\\012\\000\\000\\040!^urn\\072cid\\072.+@([^\\134.]+\\134.)(.*)$!\x02!i\\001.``000:86400::',
  },
]

const invalidRecords = [
]

describe('NAPTR record', function () {
  base.valid(NAPTR, validRecords)
  base.invalid(NAPTR, invalidRecords)

  base.getRFCs(NAPTR, validRecords[0])
  base.getFields(NAPTR, [ 'order', 'preference', 'flags', 'service', 'regexp', 'replacement' ])

  base.toBind(NAPTR, validRecords)
  base.toTinydns(NAPTR, validRecords)

  base.fromBind(NAPTR, validRecords)
  // base.fromTinydns(NAPTR, validRecords)
})
