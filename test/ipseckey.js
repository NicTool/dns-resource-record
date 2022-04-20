
import * as base from './base.js'

import IPSECKEY from '../rr/ipseckey.js'

const common = { ttl: 7200, class: 'IN', type: 'IPSECKEY' }

const validRecords = [
  {
    ...common,
    owner         : '38.2.0.192.in-addr.arpa.',
    precedence    : 10,
    'gateway type': 1,
    algorithm     : 2,
    gateway       : '192.0.2.38',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB         : '38.2.0.192.in-addr.arpa. 7200 IN IPSECKEY 10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
  },
  {
    ...common,
    owner         : '38.2.0.192.in-addr.arpa.',
    precedence    : 10,
    'gateway type': 0,
    algorithm     : 2,
    gateway       : '.',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB         : '38.2.0.192.in-addr.arpa. 7200 IN IPSECKEY 10 0 2 . AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
  },
  {
    ...common,
    owner         : '38.2.0.192.in-addr.arpa.',
    precedence    : 10,
    'gateway type': 1,
    algorithm     : 2,
    gateway       : '192.0.2.3',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB         : '38.2.0.192.in-addr.arpa. 7200 IN IPSECKEY 10 1 2 . AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
  },
  {
    ...common,
    owner         : '38.1.0.192.in-addr.arpa.',
    precedence    : 10,
    'gateway type': 3,
    algorithm     : 2,
    gateway       : 'mygateway.example.com.',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB         : '38.1.0.192.in-addr.arpa. 7200 IN     IPSECKEY 10 3 2 mygateway.example.com. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
  },
  {
    ...common,
    owner         : '0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0.1.0.0.0.0.0.2.8.b.d.0.1.0.0.2.ip6.arpa.',
    precedence    : 10,
    'gateway type': 2,
    algorithm     : 2,
    gateway       : '2001:0db8:0:8002::2000:1',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB         : '0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0.1.0.0.0.0.0.2.8.b.d.0.1.0.0.2.ip6.arpa. 7200 IN IPSECKEY 10 2 2 2001:0DB8:0:8002::2000:1 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
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
