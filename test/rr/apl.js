import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import APL from '../../rr/apl.js'
import * as base from '../base.js'

const defaults = { class: 'IN', ttl: 3600, type: 'APL' }

const validRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    'apl rdata': '1:192.0.2.1/32 !1:192.0.2.64/28 2:2001:db8::1/128',
    testB: 'example.com.\t3600\tIN\tAPL\t1:192.0.2.1/32 !1:192.0.2.64/28 2:2001:db8::1/128\n',
    testT:
      ':example.com:42:\\000\\001 \\004\\300\\000\\002\\001\\000\\001\\034\\204\\300\\000\\002@\\000\\002\\200\\020 \\001\\015\\270\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\001:3600::\n',
    testW:
      '076578616d706c6503636f6d00002a000100000e10002400012004c000020100011c84c00002400002801020010db8000000000000000000000001',
  },
  {
    ...defaults,
    owner: 'host.example.com.',
    ttl: 86400,
    'apl rdata': '1:10.0.0.0/8',
    testB: 'host.example.com.\t86400\tIN\tAPL\t1:10.0.0.0/8\n',
    testT: ':host.example.com:42:\\000\\001\\010\\001\\012:86400::\n',
  },
  {
    ...defaults,
    owner: '*.example.com.',
    ttl: 7200,
    'apl rdata': '2:2001:db8:1::/48',
    testB: '*.example.com.\t7200\tIN\tAPL\t2:2001:db8:1::/48\n',
    testT: ':*.example.com:42:\\000\\0020\\006 \\001\\015\\270\\000\\001:7200::\n',
  },
  {
    ...defaults,
    owner: 'a.',
    ttl: 2147483647,
    'apl rdata': '1:203.0.113.0/24',
    testB: 'a.\t2147483647\tIN\tAPL\t1:203.0.113.0/24\n',
    testT: ':a:42:\\000\\001\\030\\003\\313\\000q:2147483647::\n',
  },
  {
    ...defaults,
    owner: 'example.com.',
    'apl rdata': '2:2001:db8:1::1/128',
    testB: 'example.com.\t3600\tIN\tAPL\t2:2001:db8:1::1/128\n',
    testT:
      ':example.com:42:\\000\\002\\200\\020 \\001\\015\\270\\000\\001\\000\\000\\000\\000\\000\\000\\000\\000\\000\\001:3600::\n',
  },
]

const invalidRecords = [
  { ...defaults, owner: '', msg: /RFC/ },
  { ...defaults, owner: 'something*', msg: /fully/ },
  { ...defaults, owner: 'some*thing', msg: /fully/ },
  { ...defaults, owner: '*something', msg: /fully/ },
  { ...defaults, owner: 'something.*', msg: /fully/ },
  { ...defaults, 'apl rdata': '', msg: /apl rdata is required/ },
  { ...defaults, 'apl rdata': undefined, msg: /apl rdata is required/ },
  { ...defaults, ttl: '', msg: /TTL must be numeric/ },
  { ...defaults, ttl: -299, msg: /TTL must be an integer from 0 to 2147483647/ },
  { ...defaults, ttl: 2147483648, msg: /TTL must be an integer from 0 to 2147483647/ },
]

for (let i = 0; i < invalidRecords.length; i++) {
  invalidRecords[i] = { ...validRecords[0], ...invalidRecords[i] }
}

describe('APL record', function () {
  base.valid(APL, validRecords)
  base.invalid(APL, invalidRecords)

  base.getDescription(APL)
  base.getRFCs(APL, validRecords[0])
  base.getRdataFields(APL, ['apl rdata'])
  base.getFields(APL, ['apl rdata'])
  base.getCanonical(APL)
  base.getTypeId(APL, 42)
  base.getTags(APL)

  base.toBind(APL, validRecords)
  base.toWire(APL, validRecords)
  base.toTinydns(APL, validRecords)

  base.fromBind(APL, validRecords)
  base.fromTinydns(APL, validRecords)
  base.fromWire(APL, validRecords)

  it('rejects malformed items', function () {
    const apl = (rdata) => new APL({ owner: 'a.example.', ttl: 60, 'apl rdata': rdata })
    for (const [item, msg] of [
      ['3:192.0.2.0/24', /item must be/],
      ['1:192.0.2.0', /item must be/],
      ['1:192.0.2.300/24', /invalid IPv4 address/],
      ['1:192.0.2.0/33', /prefix \/33 is too long/],
      ['2:2001:db8::1::2/64', /invalid IPv6 address/],
    ]) {
      assert.throws(() => apl(item), msg, item)
    }
  })

  it('rejects wire items of an unknown family or overrunning length', function () {
    const decode = (hex) =>
      new APL(null).fromWire({
        owner: 'a.example.',
        cls: 'IN',
        ttl: 60,
        rdata: Uint8Array.from(Buffer.from(hex, 'hex')),
      })
    assert.throws(() => decode('0003180300c000'), /unknown address family 3/)
    assert.throws(() => decode('00011805c00002'), /address part overruns/)
    assert.throws(() => decode('000118'), /ends inside an item header/)
  })
})
