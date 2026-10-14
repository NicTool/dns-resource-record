import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import IPSECKEY from '../../rr/ipseckey.js'

const common = { ttl: 7200 }
const canonical = new IPSECKEY(null).getCanonical()

const valid = [
  {
    ...common,
    owner: '38.2.0.192.in-addr.arpa.',
    precedence: 10,
    'gateway type': 1,
    algorithm: 2,
    gateway: '192.0.2.38',
    publickey: 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB:
      '38.2.0.192.in-addr.arpa.\t7200\tIN\tIPSECKEY\t10\t1\t2\t192.0.2.38\tAQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==\n',
    testT:
      ':38.2.0.192.in-addr.arpa:45:\\012\\001\\002\\300\\000\\002&\\001\\003QSy\\206\\3555S;`dG\\216\\356\\262{[\\327M\\256\\024\\233n\\201\\272\\072\\005!\\257\\202\\253x\\001:7200::\n',
  },
  {
    ...common,
    owner: '38.2.0.192.in-addr.arpa.',
    precedence: 10,
    'gateway type': 0,
    algorithm: 2,
    gateway: '.',
    publickey: 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB:
      '38.2.0.192.in-addr.arpa.\t7200\tIN\tIPSECKEY\t10\t0\t2\t.\tAQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==\n',
    testT:
      ':38.2.0.192.in-addr.arpa:45:\\012\\000\\002\\001\\003QSy\\206\\3555S;`dG\\216\\356\\262{[\\327M\\256\\024\\233n\\201\\272\\072\\005!\\257\\202\\253x\\001:7200::\n',
  },
  {
    ...common,
    owner: '38.2.0.192.in-addr.arpa.',
    precedence: 10,
    'gateway type': 1,
    algorithm: 2,
    gateway: '192.0.2.38',
    publickey: 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB:
      '38.2.0.192.in-addr.arpa.\t7200\tIN\tIPSECKEY\t10\t1\t2\t192.0.2.38\tAQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==\n',
    testT:
      ':38.2.0.192.in-addr.arpa:45:\\012\\001\\002\\300\\000\\002&\\001\\003QSy\\206\\3555S;`dG\\216\\356\\262{[\\327M\\256\\024\\233n\\201\\272\\072\\005!\\257\\202\\253x\\001:7200::\n',
  },
  {
    ...common,
    owner: '38.1.0.192.in-addr.arpa.',
    precedence: 10,
    'gateway type': 3,
    algorithm: 2,
    gateway: 'mygateway.example.com.',
    publickey: 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB:
      '38.1.0.192.in-addr.arpa.\t7200\tIN\tIPSECKEY\t10\t3\t2\tmygateway.example.com.\tAQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==\n',
    testT:
      ':38.1.0.192.in-addr.arpa:45:\\012\\003\\002\\011mygateway\\007example\\003com\\000\\001\\003QSy\\206\\3555S;`dG\\216\\356\\262{[\\327M\\256\\024\\233n\\201\\272\\072\\005!\\257\\202\\253x\\001:7200::\n',
  },
  {
    ...common,
    owner: '0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0.1.0.0.0.0.0.2.8.b.d.0.1.0.0.2.ip6.arpa.',
    precedence: 10,
    'gateway type': 2,
    algorithm: 2,
    gateway: '2001:0db8:0000:8002:0000:0000:2000:0001',
    publickey: 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB:
      '0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0.1.0.0.0.0.0.2.8.b.d.0.1.0.0.2.ip6.arpa.\t7200\tIN\tIPSECKEY\t10\t2\t2\t2001:0db8:0000:8002:0000:0000:2000:0001\tAQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==\n',
    testT:
      ':0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0.1.0.0.0.0.0.2.8.b.d.0.1.0.0.2.ip6.arpa:45:\\012\\002\\002 \\001\\015\\270\\000\\000\\200\\002\\000\\000\\000\\000 \\000\\000\\001\\001\\003QSy\\206\\3555S;`dG\\216\\356\\262{[\\327M\\256\\024\\233n\\201\\272\\072\\005!\\257\\202\\253x\\001:7200::\n',
  },
  {
    ...common,
    owner: 'ipsec.simerson.com.',
    ttl: 86400,
    precedence: 1,
    'gateway type': 3,
    algorithm: 2,
    gateway: 'matt.simerson.net.',
    publickey:
      '0sAQPeOwAGDPLrDebL1q5Lg8XW9B/d9MnxqlzIYKXhvZPWEHNYGP7AwART/tmkeDNn7HPMtgM6GIwQ4p0KGLfSRoUKbjtPlRVeWYLbsnNXeFU5bchyYef0efYiKlxZdo',
    testB:
      'ipsec.simerson.com.\t86400\tIN\tIPSECKEY\t1\t3\t2\tmatt.simerson.net.\t0sAQPeOwAGDPLrDebL1q5Lg8XW9B/d9MnxqlzIYKXhvZPWEHNYGP7AwART/tmkeDNn7HPMtgM6GIwQ4p0KGLfSRoUKbjtPlRVeWYLbsnNXeFU5bchyYef0efYiKlxZdo\n',
    testT:
      ':ipsec.simerson.com:45:\\001\\003\\002\\004matt\\010simerson\\003net\\000\\322\\300\\020=\\343\\260\\000`\\317.\\260\\336l\\275j\\344\\270<]oA\\375\\337L\\237\\032\\245\\314\\206\\012^\\033\\331=a\\0075\\201\\217\\354\\014\\000E?\\355\\232G\\2036~\\307<\\313`3\\241\\210\\301\\016)\\320\\241\\213}$hP\\246\\343\\264\\371QU\\345\\230-\\273\'5w\\205S\\226\\334\\207&\\036\\177G\\237b"\\245\\305\\227h:86400::\n',
  },
  {
    owner: 'ipsec.nictool.tnpi.net.',
    precedence: 10,
    'gateway type': 1,
    algorithm: 2,
    gateway: '192.0.2.38',
    publickey: 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    testB:
      'ipsec.nictool.tnpi.net.\t3600\tIN\tIPSECKEY\t10\t1\t2\t192.0.2.38\tAQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==\n',
    testT:
      ':ipsec.nictool.tnpi.net:45:\\012\\001\\002\\300\\000\\002&\\001\\003QSy\\206\\3555S;`dG\\216\\356\\262{[\\327M\\256\\024\\233n\\201\\272\\072\\005!\\257\\202\\253x\\001:3600::\n',
    testW:
      '056970736563076e6963746f6f6c04746e7069036e657400002d000100000e1000290a0102c0000226010351537986ed35533b6064478eeeb27b5bd74dae149b6e81ba3a0521af82ab7801',
  },
]

const invalid = [
  {
    ...common,
    owner: '0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0.1.0.0.0.0.0.2.8.b.d.0.1.0.0.2.ip6.arpa.',
    precedence: 10,
    'gateway type': 4,
    algorithm: 2,
    gateway: '2001:0db8:0:8002::2000:1',
    publickey: 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    msg: /Gateway Type is invalid/,
  },
  {
    ...common,
    owner: '0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0.1.0.0.0.0.0.2.8.b.d.0.1.0.0.2.ip6.arpa.',
    precedence: 10,
    'gateway type': 3,
    algorithm: 5,
    gateway: '2001:0db8:0:8002::2000:1',
    publickey: 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    msg: /Algorithm invalid/,
  },
  { ...canonical, 'gateway type': 3, gateway: 'gw;x.example.', msg: /gateway has an unescaped delimiter/ },
  { ...canonical, 'gateway type': 3, gateway: 'gw.example', msg: /gateway must be fully qualified/ },
  { ...canonical, publickey: undefined, msg: /publickey must be a valid base64/ },
]

describe('IPSECKEY record', function () {
  base.suite(IPSECKEY, {
    typeId: 45,
    fields: ['precedence', 'gateway type', 'algorithm', 'gateway', 'publickey'],
    valid,
    invalid,
  })

  it('joins a public key that BIND splits across tokens', function () {
    const r = IPSECKEY.fromBind(
      'ipsec.example.com. 86400 IN IPSECKEY 1 3 2 gw.example.net. AQPeOwAG DPLrDebL ( 1q5Lg8XW )',
    )
    assert.equal(r.get('publickey'), 'AQPeOwAGDPLrDebL1q5Lg8XW')
  })

  it('encodes a compressed IPv6 gateway', function () {
    const r = new IPSECKEY({ ...canonical, 'gateway type': 2, gateway: '2001:DB8:0:8002::2000:1' })
    assert.equal(r.get('gateway'), '2001:0db8:0000:8002:0000:0000:2000:0001')
    assert.equal(
      Buffer.from(r.getWireRdata().subarray(3, 19)).toString('hex'),
      '20010db8000080020000000020000001',
    )
  })

  it('accepts the ECDSA and EdDSA algorithms, and no key with algorithm 0', function () {
    for (const algorithm of [3, 4])
      assert.equal(new IPSECKEY({ ...canonical, algorithm }).get('algorithm'), algorithm)
    const keyless = new IPSECKEY({ ...canonical, algorithm: 0, publickey: undefined })
    assert.equal(IPSECKEY.fromWire(keyless.toWire()).get('publickey'), '')
    assert.equal(
      new IPSECKEY({ ...canonical, 'gateway type': 3, gateway: 'GW.Example.' }).get('gateway'),
      'gw.example.',
    )
  })
})
