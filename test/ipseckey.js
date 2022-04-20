
import * as base from './base.js'

import IPSECKEY from '../rr/ipseckey.js'

const validRecords = [
  {
    owner         : '38.2.0.192.in-addr.arpa.',
    ttl           : 7200,
    class         : 'IN',
    type          : 'IPSECKEY',
    precedence    : 10,
    'gateway type': 1,
    algorithm     : 2,
    gateway       : '192.0.2.38',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB         : '38.2.0.192.in-addr.arpa. 7200 IN IPSECKEY 10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    // testT    : '',
  },
]

const invalidRecords = [
]

describe('IPSECKEY record', function () {
  base.valid(IPSECKEY, validRecords)
  base.invalid(IPSECKEY, invalidRecords, { ttl: 3600 })

  base.getDescription(IPSECKEY)
  base.getRFCs(IPSECKEY, validRecords[0])
  base.getRdataFields(IPSECKEY, [ 'precedence', 'gateway type', 'algorithm', 'gateway', 'publickey' ])
  base.getFields(IPSECKEY, [ 'precedence', 'gateway type', 'algorithm', 'gateway', 'publickey' ])
  base.getTypeId(IPSECKEY, 45)

  // base.toBind(IPSECKEY, validRecords)
  // base.toTinydns(IPSECKEY, validRecords)

  // base.fromBind(IPSECKEY, validRecords)
  // base.fromTinydns(IPSECKEY, validRecords)
})
