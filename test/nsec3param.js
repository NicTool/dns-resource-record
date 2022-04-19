
import * as base from './base.js'

import NSEC3PARAM from '../rr/nsec3param.js'

const validRecords = [
]

const invalidRecords = [
]

describe('NSEC3PARAM record', function () {
  base.valid(NSEC3PARAM, validRecords)
  base.invalid(NSEC3PARAM, invalidRecords, { ttl: 3600 })

  base.getDescription(NSEC3PARAM)
  base.getRFCs(NSEC3PARAM, validRecords[0])
  base.getFields(NSEC3PARAM, [ 'hash algorithm', 'flags', 'iterations', 'salt' ])
  base.getTypeId(NSEC3PARAM, 51)

  // base.toBind(NSEC3PARAM, validRecords)
  // base.toTinydns(NSEC3PARAM, validRecords)

  // base.fromBind(NSEC3PARAM, validRecords)
  // base.fromTinydns(NSEC3PARAM, validRecords)
})
