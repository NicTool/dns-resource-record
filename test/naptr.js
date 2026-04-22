import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from './base.js'

import NAPTR from '../rr/naptr.js'

const validRecords = [
  {
    owner: 'cid.urn.arpa.',
    ttl: 86400,
    class: 'IN',
    type: 'NAPTR',
    order: 100,
    preference: 10,
    flags: '',
    service: '',
    regexp: '!^urn:cid:.+@([^\\.]+\\.)(.*)$!\x02!i',
    replacement: '.',
    testB: 'cid.urn.arpa.\t86400\tIN\tNAPTR\t100\t10\t""\t""\t"!^urn:cid:.+@([^\\.]+\\.)(.*)$!\x02!i"\t.\n',
    testT:
      ':cid.urn.arpa:35:\\000\\144\\000\\012\\000\\000\\040!^urn\\072cid\\072.+@([^\\134.]+\\134.)(.*)$!\x02!i\\001.\\000:86400::\n',
    testW:
      '036369640375726e046172706100002300010001518000280064000a000020215e75726e3a6369643a2e2b40285b5e5c2e5d2b5c2e29282e2a29242102216900',
  },
]

const invalidRecords = [
  {
    owner: 'cid.urn.arpa.',
    ttl: 86400,
    class: 'IN',
    type: 'NAPTR',
    order: 100,
    preference: 10,
    flags: 'X',
    service: '',
    regexp: '',
    replacement: '.',
    msg: /flags are invalid/i,
  },
]

describe('NAPTR record', function () {
  base.valid(NAPTR, validRecords)
  base.invalid(NAPTR, invalidRecords)

  base.getDescription(NAPTR)
  base.getRFCs(NAPTR, validRecords[0])
  base.getFields(NAPTR, ['order', 'preference', 'flags', 'service', 'regexp', 'replacement'])
  base.getCanonical(NAPTR)
  base.getTypeId(NAPTR, 35)
  base.getTags(NAPTR)

  base.toBind(NAPTR, validRecords)
  base.toWire(NAPTR, validRecords)
  base.toTinydns(NAPTR, validRecords)

  base.fromBind(NAPTR, validRecords)
  base.fromTinydns(NAPTR, validRecords)

  it('throws on invalid NAPTR BIND line', function () {
    assert.throws(() => NAPTR.fromBind('this is not valid naptr\n'), /Invalid NAPTR BIND line/)
  })
})
