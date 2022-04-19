
import * as base from './base.js'

import NSEC3 from '../rr/nsec3.js'

const validRecords = [
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

  // base.toBind(NSEC3, validRecords)
  // base.toTinydns(NSEC3, validRecords)

  // base.fromBind(NSEC3, validRecords)
  // base.fromTinydns(NSEC3, validRecords)
})
