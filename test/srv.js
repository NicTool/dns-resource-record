import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from './base.js'

import SRV from '../rr/srv.js'

const defaults = { class: 'IN', ttl: 3600, type: 'SRV' }

const validRecords = [
  {
    ...defaults,
    owner: '_imaps._tcp.example.com.',
    priority: 1,
    weight: 0,
    port: 993,
    target: 'mail.example.com.',
    testB: '_imaps._tcp.example.com.\t3600\tIN\tSRV\t1\t0\t993\tmail.example.com.\n',
    testT:
      ':_imaps._tcp.example.com:33:\\000\\001\\000\\000\\003\\341\\004mail\\007example\\003com\\000:3600::\n',
  },
  {
    ...defaults,
    owner: '_sip._tls.example.com.',
    priority: 100,
    weight: 1,
    port: 443,
    target: 'sipdir.online.lync.com.',
    testB: '_sip._tls.example.com.\t3600\tIN\tSRV\t100\t1\t443\tsipdir.online.lync.com.\n',
    testT:
      ':_sip._tls.example.com:33:\\000\\144\\000\\001\\001\\273\\006sipdir\\006online\\004lync\\003com\\000:3600::\n',
  },
  {
    owner: '_imaps._tcp.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'SRV',
    priority: 1,
    weight: 0,
    port: 993,
    target: 'mail.nictool.tnpi.net.',
    testB: '_imaps._tcp.nictool.tnpi.net.\t3600\tIN\tSRV\t1\t0\t993\tmail.nictool.tnpi.net.\n',
    testT:
      ':_imaps._tcp.nictool.tnpi.net:33:\\000\\001\\000\\000\\003\\341\\004mail\\007nictool\\004tnpi\\003net\\000:3600::\n',
    testW:
      '065f696d617073045f746370076e6963746f6f6c04746e7069036e6574000021000100000e10001d0001000003e1046d61696c076e6963746f6f6c04746e7069036e657400',
  },
  {
    owner: '_https._tcp.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'SRV',
    priority: 1,
    weight: 0,
    port: 443,
    target: 'www.nictool.tnpi.net.',
    testB: '_https._tcp.nictool.tnpi.net.\t3600\tIN\tSRV\t1\t0\t443\twww.nictool.tnpi.net.\n',
    testT:
      ':_https._tcp.nictool.tnpi.net:33:\\000\\001\\000\\000\\001\\273\\003www\\007nictool\\004tnpi\\003net\\000:3600::\n',
    testW:
      '065f6874747073045f746370076e6963746f6f6c04746e7069036e6574000021000100000e10001c0001000001bb03777777076e6963746f6f6c04746e7069036e657400',
  },
  {
    owner: '_sip._udp.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'SRV',
    priority: 10,
    weight: 0,
    port: 5060,
    target: 'sip.nictool.tnpi.net.',
    testB: '_sip._udp.nictool.tnpi.net.\t3600\tIN\tSRV\t10\t0\t5060\tsip.nictool.tnpi.net.\n',
    testT:
      ':_sip._udp.nictool.tnpi.net:33:\\000\\012\\000\\000\\023\\304\\003sip\\007nictool\\004tnpi\\003net\\000:3600::\n',
    testW:
      '045f736970045f756470076e6963746f6f6c04746e7069036e6574000021000100000e10001c000a000013c403736970076e6963746f6f6c04746e7069036e657400',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    target: 'not-full-qualified.example.com',
    msg: /must be a 16-bit integer/,
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    target: '192.168.0.1',
    msg: /must be a 16-bit integer/,
  },
]

describe('SRV record', function () {
  base.valid(SRV, validRecords)
  base.invalid(SRV, invalidRecords)

  base.getDescription(SRV)
  base.getRFCs(SRV, validRecords[0])
  base.getFields(SRV, ['priority', 'weight', 'port', 'target'])
  base.getCanonical(SRV)
  base.getTypeId(SRV, 33)
  base.getTags(SRV)

  base.toBind(SRV, validRecords)
  base.toWire(SRV, validRecords)
  base.toTinydns(SRV, validRecords)

  base.fromBind(SRV, validRecords)
  base.fromTinydns(SRV, validRecords)

  for (const val of validRecords) {
    if (!val.testT) continue
    it(`imports tinydns SRV (generic) record (${val.owner})`, async function () {
      const r = new SRV({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of ['owner', 'target', 'priority', 'weight', 'port', 'ttl']) {
        assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }

  it(`imports tinydns SRV (S) record`, async function () {
    const val = validRecords[0]
    const r = new SRV({
      tinyline: 'S_imaps._tcp.example.com:mail.example.com:993:1:0:3600::',
    })
    if (process.env.DEBUG) console.dir(r)
    for (const f of ['owner', 'target', 'priority', 'weight', 'port', 'ttl']) {
      assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
    }
  })
})
