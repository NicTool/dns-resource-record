import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import NXT from '../../rr/nxt.js'

const valid = [
  {
    owner: 'big.example.com.',
    ttl: 86400,
    'next domain': 'medium.example.com.',
    'type bit map': 'A SIG NXT',
    testB: `big.example.com.\t86400\tIN\tNXT\tmedium.example.com.\tA SIG NXT\n`,
    testT: ':big.example.com:30:\\006medium\\007example\\003com\\000@\\000\\000\\202:86400::\n',
    testW:
      '03626967076578616d706c6503636f6d00001e0001000151800018066d656469756d076578616d706c6503636f6d0040000082',
  },
]

// RFC 2535 §5.2
const invalid = [
  { ...valid[0], 'type bit map': 'A CAA', msg: /type CAA is outside 1-127/ },
  { ...valid[0], 'type bit map': 'A BOGUS', msg: /invalid DNS type: BOGUS/ },
]

describe('NXT record', function () {
  base.suite(NXT, {
    typeId: 30,
    fields: ['next domain', 'type bit map'],
    valid,
    invalid,
  })

  it('stores the type list in type order', function () {
    const nxt = (types) =>
      new NXT({ owner: 'a.example.', ttl: 60, 'next domain': 'b.example.', 'type bit map': types })
    assert.equal(nxt('nxt a').get('type bit map'), 'A NXT')
  })
})
