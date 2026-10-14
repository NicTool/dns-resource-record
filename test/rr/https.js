import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import HTTPS from '../../rr/https.js'

const defaults = { class: 'IN', ttl: 3600, type: 'HTTPS' }

const validRecords = [
  {
    ...defaults,
    owner: '_8443._foo.api.example.com.',
    ttl: 7200,
    priority: 1,
    'target name': 'svc4.example.net.',
    params: 'alpn="bar" port=8004',
    testB: '_8443._foo.api.example.com.\t7200\tIN\tHTTPS\t1\tsvc4.example.net.\talpn="bar" port=8004\n',
    testT:
      ':_8443._foo.api.example.com:65:\\000\\001\\004svc4\\007example\\003net\\000\\000\\001\\000\\004\\003bar\\000\\003\\000\\002\\037D:7200::\n',
    testW:
      '055f38343433045f666f6f03617069076578616d706c6503636f6d000041000100001c20002200010473766334076578616d706c65036e6574000001000403626172000300021f44',
  },
  {
    ...defaults,
    owner: '_8080._foo.example.com.',
    priority: 0,
    'target name': 'foosvc.example.net.',
    params: '',
    testB: '_8080._foo.example.com.\t3600\tIN\tHTTPS\t0\tfoosvc.example.net.\t\n',
    testT: ':_8080._foo.example.com:65:\\000\\000\\006foosvc\\007example\\003net\\000:3600::\n',
    testW:
      '055f38303830045f666f6f076578616d706c6503636f6d000041000100000e100016000006666f6f737663076578616d706c65036e657400',
  },
  /*
  _1234._bar.example.com. 300 IN HTTPS 1 svc1.example.net. ( ech="111..." ipv6hint=2001:0db8:0000:0000:0000:0000:0000:0001 port=1234 )
                                 HTTPS 2 svc2.example.net. ( ech="222..." ipv6hint=2001:db8::2 port=1234 )
*/
  {
    owner: 'www.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'HTTPS',
    priority: 0,
    'target name': 'nictool.tnpi.net.',
    params: '',
    testB: 'www.nictool.tnpi.net.\t3600\tIN\tHTTPS\t0\tnictool.tnpi.net.\t\n',
    testT: ':www.nictool.tnpi.net:65:\\000\\000\\007nictool\\004tnpi\\003net\\000:3600::\n',
    testW:
      '03777777076e6963746f6f6c04746e7069036e6574000041000100000e1000140000076e6963746f6f6c04746e7069036e657400',
  },
  {
    ...defaults,
    owner: 'nodefaultalpn.example.com.',
    priority: 1,
    'target name': 'example.com.',
    params: 'alpn="h2" no-default-alpn',
    testB: 'nodefaultalpn.example.com.\t3600\tIN\tHTTPS\t1\texample.com.\talpn="h2" no-default-alpn\n',
    testT:
      ':nodefaultalpn.example.com:65:\\000\\001\\007example\\003com\\000\\000\\001\\000\\003\\002h2\\000\\002\\000\\000:3600::\n',
  },
  {
    ...defaults,
    owner: 'echparam.example.com.',
    priority: 1,
    'target name': 'example.com.',
    params: 'ech=AQIDBA==',
    testB: 'echparam.example.com.\t3600\tIN\tHTTPS\t1\texample.com.\tech=AQIDBA==\n',
    testT:
      ':echparam.example.com:65:\\000\\001\\007example\\003com\\000\\000\\005\\000\\004\\001\\002\\003\\004:3600::\n',
    testW:
      '08656368706172616d076578616d706c6503636f6d000041000100000e1000170001076578616d706c6503636f6d000005000401020304',
  },
  {
    ...defaults,
    owner: 'ipv6hint.example.com.',
    priority: 1,
    'target name': 'example.com.',
    params: 'ipv6hint=2001:0db8:0000:0000:0000:0000:0000:0001',
    testB:
      'ipv6hint.example.com.\t3600\tIN\tHTTPS\t1\texample.com.\tipv6hint=2001:0db8:0000:0000:0000:0000:0000:0001\n',
    testT:
      ':ipv6hint.example.com:65:\\000\\001\\007example\\003com\\000\\000\\006\\000\\020 \\001\\015\\270\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\001:3600::\n',
    testW:
      '086970763668696e74076578616d706c6503636f6d000041000100000e1000230001076578616d706c6503636f6d000006001020010db8000000000000000000000001',
  },
  {
    ...defaults,
    owner: 'unknownkey.example.com.',
    priority: 1,
    'target name': 'example.com.',
    params: 'key1234=test',
    testB: 'unknownkey.example.com.\t3600\tIN\tHTTPS\t1\texample.com.\tkey1234=test\n',
    testT: ':unknownkey.example.com:65:\\000\\001\\007example\\003com\\000\\004\\322\\000\\004test:3600::\n',
  },
]

const invalidRecords = [
  // {
  //   ...defaults,
  //   owner : 'test.example.com.',
  //   'target name': 'not-full-qualified.example.com',
  //   params  : /must be a 16-bit integer/,
  // },
]

describe('HTTPS record', function () {
  base.valid(HTTPS, validRecords)
  base.invalid(HTTPS, invalidRecords)

  base.getDescription(HTTPS)
  base.getRFCs(HTTPS, validRecords[0])
  base.getFields(HTTPS, ['priority', 'target name', 'params'])
  base.getCanonical(HTTPS)
  base.getTypeId(HTTPS, 65)
  base.getTags(HTTPS)

  base.toBind(HTTPS, validRecords)
  base.toWire(HTTPS, validRecords)
  base.toTinydns(HTTPS, validRecords)

  base.fromBind(HTTPS, validRecords)
  base.fromTinydns(HTTPS, validRecords)
  base.fromWire(HTTPS, validRecords)

  it('throws when fromTinydns RDATA is too short', function () {
    assert.throws(() => HTTPS.fromTinydns(':example.com:65:AB:3600::\n'), /wire name runs past the end/)
  })

  it('rejects switching a record with params to AliasMode', function () {
    const r = new HTTPS({
      owner: 'a.example.',
      ttl: 60,
      type: 'HTTPS',
      priority: 1,
      'target name': '.',
      params: 'alpn=h2',
    })
    assert.throws(() => r.setPriority(0), /AliasMode \(priority 0\) takes no params/)
    assert.equal(r.get('priority'), 1)
  })
})
