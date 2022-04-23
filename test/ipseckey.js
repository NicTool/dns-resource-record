
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
    testB         : '38.2.0.192.in-addr.arpa.\t7200\tIN\tIPSECKEY\t10\t1\t2\t192.0.2.38\tAQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==\n',
    testT         : ':38.2.0.192.in-addr.arpa:45:\\012\\001\\002\\300\\000\\002\\046\\001\\003QSy\\206\\3555S\\073\\140dG\\216\\356\\262\\173\\133\\327M\\256\\024\\233n\\201\\272\\072\\005\\041\\257\\202\\253x\\001:7200::\n',
  },
  {
    ...common,
    owner         : '38.2.0.192.in-addr.arpa.',
    precedence    : 10,
    'gateway type': 0,
    algorithm     : 2,
    gateway       : '.',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB         : '38.2.0.192.in-addr.arpa.\t7200\tIN\tIPSECKEY\t10\t0\t2\t.\tAQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==\n',
    testT         : ':38.2.0.192.in-addr.arpa:45:\\012\\000\\002.\\001\\003QSy\\206\\3555S\\073\\140dG\\216\\356\\262\\173\\133\\327M\\256\\024\\233n\\201\\272\\072\\005\\041\\257\\202\\253x\\001:7200::\n',
  },
  {
    ...common,
    owner         : '38.2.0.192.in-addr.arpa.',
    precedence    : 10,
    'gateway type': 1,
    algorithm     : 2,
    gateway       : '192.0.2.38',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB         : '38.2.0.192.in-addr.arpa.\t7200\tIN\tIPSECKEY\t10\t1\t2\t192.0.2.38\tAQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==\n',
    testT         : ':38.2.0.192.in-addr.arpa:45:\\012\\001\\002\\300\\000\\002\\046\\001\\003QSy\\206\\3555S\\073\\140dG\\216\\356\\262\\173\\133\\327M\\256\\024\\233n\\201\\272\\072\\005\\041\\257\\202\\253x\\001:7200::\n',
  },
  {
    ...common,
    owner         : '38.1.0.192.in-addr.arpa.',
    precedence    : 10,
    'gateway type': 3,
    algorithm     : 2,
    gateway       : 'mygateway.example.com.',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB         : '38.1.0.192.in-addr.arpa.\t7200\tIN\tIPSECKEY\t10\t3\t2\tmygateway.example.com.\tAQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==\n',
    testT         : ':38.1.0.192.in-addr.arpa:45:\\012\\003\\002\\011mygateway\\007example\\003com\\000\\001\\003QSy\\206\\3555S\\073\\140dG\\216\\356\\262\\173\\133\\327M\\256\\024\\233n\\201\\272\\072\\005\\041\\257\\202\\253x\\001:7200::\n',
  },
  {
    ...common,
    owner         : '0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0.1.0.0.0.0.0.2.8.b.d.0.1.0.0.2.ip6.arpa.',
    precedence    : 10,
    'gateway type': 2,
    algorithm     : 2,
    gateway       : '2001:0db8:0:8002::2000:1',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB         : '0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0.1.0.0.0.0.0.2.8.b.d.0.1.0.0.2.ip6.arpa.\t7200\tIN\tIPSECKEY\t10\t2\t2\t2001:0db8:0:8002::2000:1\tAQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==\n',
  },
  {
    ...common,
    owner         : 'ipsec.simerson.com.',
    ttl           : 86400,
    precedence    : 1,
    'gateway type': 3,
    algorithm     : 2,
    gateway       : 'matt.simerson.net.',
    publickey     : '0sAQPeOwAGDPLrDebL1q5Lg8XW9B/d9MnxqlzIYKXhvZPWEHNYGP7AwART/tmkeDNn7HPMtgM6GIwQ4p0KGLfSRoUKbjtPlRVeWYLbsnNXeFU5bchyYef0efYiKlxZdo',
    testB         : 'ipsec.simerson.com.\t86400\tIN\tIPSECKEY\t1\t3\t2\tmatt.simerson.net.\t0sAQPeOwAGDPLrDebL1q5Lg8XW9B/d9MnxqlzIYKXhvZPWEHNYGP7AwART/tmkeDNn7HPMtgM6GIwQ4p0KGLfSRoUKbjtPlRVeWYLbsnNXeFU5bchyYef0efYiKlxZdo\n',
    testT         : ':ipsec.simerson.com:45:\\001\\003\\002\\004matt\\010simerson\\003net\\000\\322\\300\\020\\075\\343\\260\\000\\140\\317.\\260\\336l\\275j\\344\\270\\074\\135oA\\375\\337L\\237\\032\\245\\314\\206\\012\\136\\033\\331\\075a\\0075\\201\\217\\354\\014\\000E\\077\\355\\232G\\2036\\176\\307\\074\\313\\1403\\241\\210\\301\\016\\051\\320\\241\\213\\175\\044hP\\246\\343\\264\\371QU\\345\\230-\\273\\0475w\\205S\\226\\334\\207\\046\\036\\177G\\237b\\042\\245\\305\\227h:86400::\n',
  },
]

const invalidRecords = [
  {
    ...common,
    owner         : '0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0.1.0.0.0.0.0.2.8.b.d.0.1.0.0.2.ip6.arpa.',
    precedence    : 10,
    'gateway type': 4,
    algorithm     : 2,
    gateway       : '2001:0db8:0:8002::2000:1',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    msg           : /Gateway Type is invalid/,
  },
  {
    ...common,
    owner         : '0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0.1.0.0.0.0.0.2.8.b.d.0.1.0.0.2.ip6.arpa.',
    precedence    : 10,
    'gateway type': 3,
    algorithm     : 3,
    gateway       : '2001:0db8:0:8002::2000:1',
    publickey     : 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    msg           : /Algorithm invalid/,
  },
]

describe('IPSECKEY record', function () {
  base.valid(IPSECKEY, validRecords)
  base.invalid(IPSECKEY, invalidRecords)

  base.getDescription(IPSECKEY)
  base.getRFCs(IPSECKEY, validRecords[0])
  base.getRdataFields(IPSECKEY, [ 'precedence', 'gateway type', 'algorithm', 'gateway', 'publickey' ])
  base.getFields(IPSECKEY, [ 'precedence', 'gateway type', 'algorithm', 'gateway', 'publickey' ])
  base.getTypeId(IPSECKEY, 45)

  base.toBind(IPSECKEY, validRecords)
  base.toTinydns(IPSECKEY, validRecords)

  base.fromBind(IPSECKEY, validRecords)
  base.fromTinydns(IPSECKEY, validRecords)
})
