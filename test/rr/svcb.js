import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import SVCB from '../../rr/svcb.js'

const defaults = { class: 'IN', ttl: 3600, type: 'SVCB' }

const validRecords = [
  {
    ...defaults,
    owner: '_8443._foo.api.example.com.',
    ttl: 7200,
    priority: 1,
    'target name': 'svc4.example.net.',
    params: 'alpn="bar" port=8004',
    testB: '_8443._foo.api.example.com.\t7200\tIN\tSVCB\t1\tsvc4.example.net.\talpn="bar" port=8004\n',
    testT:
      ':_8443._foo.api.example.com:64:\\000\\001\\004svc4\\007example\\003net\\000\\000\\001\\000\\004\\003bar\\000\\003\\000\\002\\037D:7200::\n',
    testW:
      '055f38343433045f666f6f03617069076578616d706c6503636f6d000040000100001c20002200010473766334076578616d706c65036e6574000001000403626172000300021f44',
  },
  {
    ...defaults,
    owner: '_8080._foo.example.com.',
    priority: 0,
    'target name': 'foosvc.example.net.',
    params: '',
    testB: '_8080._foo.example.com.\t3600\tIN\tSVCB\t0\tfoosvc.example.net.\n',
    testT: ':_8080._foo.example.com:64:\\000\\000\\006foosvc\\007example\\003net\\000:3600::\n',
    testW:
      '055f38303830045f666f6f076578616d706c6503636f6d000040000100000e100016000006666f6f737663076578616d706c65036e657400',
  },
  /*
  _1234._bar.example.com. 300 IN SVCB 1 svc1.example.net. ( ech="111..." ipv6hint=2001:0db8:0000:0000:0000:0000:0000:0001 port=1234 )
                                 SVCB 2 svc2.example.net. ( ech="222..." ipv6hint=2001:db8::2 port=1234 )
*/
  {
    owner: '_443._tcp.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'SVCB',
    priority: 1,
    'target name': 'nictool.tnpi.net.',
    params: '',
    testB: '_443._tcp.nictool.tnpi.net.\t3600\tIN\tSVCB\t1\tnictool.tnpi.net.\n',
    testT: ':_443._tcp.nictool.tnpi.net:64:\\000\\001\\007nictool\\004tnpi\\003net\\000:3600::\n',
    testW:
      '045f343433045f746370076e6963746f6f6c04746e7069036e6574000040000100000e1000140001076e6963746f6f6c04746e7069036e657400',
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

describe('SVCB record', function () {
  base.valid(SVCB, validRecords)
  base.invalid(SVCB, invalidRecords)

  base.getDescription(SVCB)
  base.getRFCs(SVCB, validRecords[0])
  base.getFields(SVCB, ['priority', 'target name', 'params'])
  base.getCanonical(SVCB)
  base.getTypeId(SVCB, 64)
  base.getTags(SVCB)

  base.toBind(SVCB, validRecords)
  base.toWire(SVCB, validRecords)
  base.toTinydns(SVCB, validRecords)

  base.fromBind(SVCB, validRecords)
  base.fromTinydns(SVCB, validRecords)
  base.fromWire(SVCB, validRecords)

  it('throws when fromTinydns RDATA is too short', function () {
    assert.throws(() => SVCB.fromTinydns(':example.com:64:AB:3600::\n'), /wire name runs past the end/)
  })

  describe('params semantics (RFC 9460)', function () {
    const svcb = (priority, params) =>
      new SVCB({ owner: 'a.example.', ttl: 60, type: 'SVCB', priority, 'target name': 'b.example.', params })

    it('rejects params in AliasMode', function () {
      assert.throws(() => svcb(0, 'alpn=h2'), /AliasMode \(priority 0\) takes no params/)
      assert.equal(svcb(0, '').get('params'), '')
    })

    it('rejects switching a record with params to AliasMode', function () {
      const r = svcb(1, 'alpn=h2')
      assert.throws(() => r.setPriority(0), /AliasMode \(priority 0\) takes no params/)
      assert.equal(r.get('priority'), 1)
    })

    it('rejects no-default-alpn without alpn', function () {
      assert.throws(() => svcb(1, 'no-default-alpn'), /no-default-alpn requires alpn/)
    })

    it('rejects a mandatory key that is absent', function () {
      assert.throws(() => svcb(1, 'mandatory=port alpn=h2'), /mandatory keys missing: port/)
      assert.throws(() => svcb(1, 'MANDATORY=port alpn=h2'), /mandatory keys missing: port/)
      assert.throws(() => svcb(1, 'key0=key3 alpn=h2'), /mandatory keys missing: port/)
      assert.equal(svcb(1, 'mandatory=port port=443').get('params'), 'mandatory=port port=443')
    })

    it('rejects an unknown key when the record is created', function () {
      assert.throws(() => svcb(1, 'alnp=h2'), /SVCB: unknown SvcParamKey: alnp/)
    })
  })
})
