
import * as base from './base.js'

import OPENPGPKEY from '../rr/openpgpkey.js'

const validRecords = [
  // {
  //   owner    : 'example.com.',
  //   ttl      : 3600,
  //   class    : 'IN',
  //   type     : 'OPENPGPKEY',
  //   'public key': ``,
  //   testB    : '',
  //   testT    : '',
  // },
]

const invalidRecords = [
]

describe('OPENPGPKEY record', function () {
  base.valid(OPENPGPKEY, validRecords)
  base.invalid(OPENPGPKEY, invalidRecords, { ttl: 3600 })

  base.getDescription(OPENPGPKEY)
  base.getRFCs(OPENPGPKEY)
  base.getFields(OPENPGPKEY, [ 'public key' ])
  base.getTypeId(OPENPGPKEY, 61)

  base.toBind(OPENPGPKEY, validRecords)
  // base.toTinydns(OPENPGPKEY, validRecords)

  base.fromBind(OPENPGPKEY, validRecords)
  // base.fromTinydns(OPENPGPKEY, validRecords)
})
