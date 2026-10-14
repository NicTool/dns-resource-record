import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import NAPTR from '../../rr/naptr.js'

const valid = [
  {
    owner: 'cid.urn.arpa.',
    ttl: 86400,
    order: 100,
    preference: 10,
    flags: '',
    service: '',
    regexp: '!^urn:cid:.+@([^\\.]+\\.)(.*)$!\x02!i',
    replacement: '.',
    testB:
      'cid.urn.arpa.\t86400\tIN\tNAPTR\t100\t10\t""\t""\t"!^urn:cid:.+@([^\\\\.]+\\\\.)(.*)$!\\002!i"\t.\n',
    testT:
      ':cid.urn.arpa:35:\\000d\\000\\012\\000\\000 !^urn\\072cid\\072.+@([^\\134.]+\\134.)(.*)$!\\002!i\\000:86400::\n',
    testW:
      '036369640375726e046172706100002300010001518000280064000a000020215e75726e3a6369643a2e2b40285b5e5c2e5d2b5c2e29282e2a29242102216900',
  },
]

const invalid = [
  {
    owner: 'cid.urn.arpa.',
    ttl: 86400,
    order: 100,
    preference: 10,
    flags: 'X',
    service: '',
    regexp: '',
    replacement: '.',
    msg: /flags are invalid/i,
  },
  { bindline: 'this is not valid naptr\n', msg: /expected NAPTR, got IS/ },
]

describe('NAPTR record', function () {
  base.suite(NAPTR, {
    typeId: 35,
    fields: ['order', 'preference', 'flags', 'service', 'regexp', 'replacement'],
    valid,
    invalid,
  })

  it('exports MaraDNS csv2 with ;-separated strings', function () {
    const r = new NAPTR({ ...valid[0], replacement: 'sip.example.com.' })
    assert.equal(
      r.toMaraDNS(),
      "cid.urn.arpa.\t+86400\tNAPTR\t100\t10\t'';'';'!^urn:cid:.+@([^\\.]+\\.)(.*)$!'\\x02'!i'\tsip.example.com. ~\n",
    )
  })

  it('exports MaraDNS RAW when the replacement is the root, which csv2 cannot name', function () {
    assert.match(new NAPTR(valid[0]).toMaraDNS(), /\tRAW 35\t/)
  })
})
