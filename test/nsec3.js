
import * as base from './base.js'

import NSEC3 from '../rr/nsec3.js'

const defaults = { class: 'IN', ttl: 3600, type: 'NSEC3' }

const validRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    'hash algorithm': 1,
    flags: 1,
    iterations: 12,
    salt: 'aabbccdd',
    'type bit maps': 'A\tRRSIG',
    'next hashed owner name': '2vptu5timamqttgl4luu9kg21e0aor3s',
    testB: 'test.example.com.\t3600\tIN\tNSEC3\t1\t1\t12\taabbccdd\t(2vptu5timamqttgl4luu9kg21e0aor3s\tA\tRRSIG)\n',
    testT: ':test.example.com:50:\\001\\001\\000\\014aabbccdd2vptu5timamqttgl4luu9kg21e0aor3sA\\011RRSIG:3600::\n',
  },
]

const invalidRecords = [
]

describe('NSEC3 record', function () {
  base.valid(NSEC3, validRecords)
  base.invalid(NSEC3, invalidRecords, { ttl: 3600 })

  base.getDescription(NSEC3)
  base.getRFCs(NSEC3, validRecords[0])
  base.getFields(NSEC3, [ 'hash algorithm', 'flags', 'iterations', 'salt',  'next hashed owner name', 'type bit maps' ])
  base.getTypeId(NSEC3, 50)

  base.toBind(NSEC3, validRecords)
  base.toTinydns(NSEC3, validRecords)

  base.fromBind(NSEC3, validRecords)
  // base.fromTinydns(NSEC3, validRecords)
})
