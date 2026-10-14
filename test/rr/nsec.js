import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import NSEC from '../../rr/nsec.js'

const validRecords = [
  {
    owner: 'alfa.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'NSEC',
    'next domain': 'host.example.com.',
    'type bit maps': 'A MX RRSIG NSEC TYPE1234',
    testB: `alfa.example.com.\t86400\tIN\tNSEC\thost.example.com.\tA MX RRSIG NSEC TYPE1234\n`,
    testT:
      ':alfa.example.com:47:\\004host\\007example\\003com\\000\\000\\006@\\001\\000\\000\\000\\003\\004\\033\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000 :86400::\n',
    testW:
      '04616c6661076578616d706c6503636f6d00002f000100015180003704686f7374076578616d706c6503636f6d000006400100000003041b000000000000000000000000000000000000000000000000000020',
  },
]

const invalidRecords = [
  // {
  // },
]

describe('NSEC record', function () {
  base.valid(NSEC, validRecords)
  base.invalid(NSEC, invalidRecords, { ttl: 3600 })

  base.getDescription(NSEC)
  base.getRFCs(NSEC, validRecords[0])
  base.getFields(NSEC, ['next domain', 'type bit maps'])
  base.getCanonical(NSEC)
  base.getTypeId(NSEC, 47)
  base.getTags(NSEC)

  base.toBind(NSEC, validRecords)
  base.toWire(NSEC, validRecords)
  base.toTinydns(NSEC, validRecords)

  base.fromBind(NSEC, validRecords)
  base.fromTinydns(NSEC, validRecords)
  base.fromWire(NSEC, validRecords)

  it('stores the type list in type order and rejects unknown types', function () {
    const nsec = (types) =>
      new NSEC({ owner: 'a.example.', ttl: 60, 'next domain': 'b.example.', 'type bit maps': types })
    assert.equal(nsec('rrsig nsec A').get('type bit maps'), 'A RRSIG NSEC')
    assert.throws(() => nsec('A BOGUS'), /type bit maps: invalid DNS type: BOGUS/)
  })
})
