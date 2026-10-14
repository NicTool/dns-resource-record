import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import AAAA from '../../rr/aaaa.js'
import * as base from '../base.js'

const valid = [
  {
    owner: 'test.example.com.',
    address: '2001:0db8:0020:000a:0000:0000:0000:0004',
    testB: 'test.example.com.\t3600\tIN\tAAAA\t2001:db8:20:a::4\n',
    testT:
      ':test.example.com:28: \\001\\015\\270\\000 \\000\\012\\000\\000\\000\\000\\000\\000\\000\\004:3600::\n',
    testW: '0474657374076578616d706c6503636f6d00001c000100000e10001020010db80020000a0000000000000004',
  },
  {
    owner: 'test.example.com.',
    ttl: 2147483647,
    address: '2001:0db8:0020:000a:0000:0000:0000:0004',
    testB: 'test.example.com.\t2147483647\tIN\tAAAA\t2001:db8:20:a::4\n',
    testT:
      ':test.example.com:28: \\001\\015\\270\\000 \\000\\012\\000\\000\\000\\000\\000\\000\\000\\004:2147483647::\n',
    testW: '0474657374076578616d706c6503636f6d00001c00017fffffff001020010db80020000a0000000000000004',
  },
  {
    owner: 'a.',
    ttl: 86400,
    address: '0000:0000:0000:0000:0000:0000:0000:0001',
    testB: 'a.\t86400\tIN\tAAAA\t::1\n',
    testT: ':a:28:\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\001:86400::\n',
    testW: '016100001c000100015180001000000000000000000000000000000001',
  },
  {
    owner: '*.example.com.',
    address: '2001:0db8:0000:0000:0000:0000:0002:0001',
    testB: '*.example.com.\t3600\tIN\tAAAA\t2001:db8::2:1\n',
    testT:
      ':*.example.com:28: \\001\\015\\270\\000\\000\\000\\000\\000\\000\\000\\000\\000\\002\\000\\001:3600::\n',
    testW: '012a076578616d706c6503636f6d00001c000100000e10001020010db8000000000000000000020001',
  },
  {
    owner: 'nictool.tnpi.net.',
    address: '2001:0db8:0000:0000:0000:0000:0000:0001',
    testB: 'nictool.tnpi.net.\t3600\tIN\tAAAA\t2001:db8::1\n',
    testT:
      ':nictool.tnpi.net:28: \\001\\015\\270\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\001:3600::\n',
    testW: '076e6963746f6f6c04746e7069036e657400001c000100000e10001020010db8000000000000000000000001',
  },
  {
    owner: 'www.nictool.tnpi.net.',
    address: '2001:0db8:0000:0000:0000:0000:0000:0002',
    testB: 'www.nictool.tnpi.net.\t3600\tIN\tAAAA\t2001:db8::2\n',
    testT:
      ':www.nictool.tnpi.net:28: \\001\\015\\270\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\002:3600::\n',
    testW: '03777777076e6963746f6f6c04746e7069036e657400001c000100000e10001020010db8000000000000000000000002',
  },
]

const invalid = [
  { owner: '', msg: /RFC/ },
  { owner: 'something*', msg: /fully/ },
  { owner: 'some*thing', msg: /fully/ },
  { owner: '*something', msg: /fully/ },
  { owner: 'something.*', msg: /fully/ },
  { address: '192.0.2.204', msg: /address must be IPv6/ },
  { address: '2001:db8::zzzz', msg: /address must be IPv6/ },
  { address: '', msg: /address is required/ },
  { address: undefined, msg: /address is required/ },
  { ttl: '', msg: /TTL must be numeric/ },
  { ttl: -299, msg: /TTL must be an integer from 0 to 2147483647/ },
  { ttl: 2147483648, msg: /TTL must be an integer from 0 to 2147483647/ },
  { owner: 'a.example.', address: '::ffff:192.0.2.300', msg: /IPv6/ },
]

for (let i = 0; i < invalid.length; i++) {
  invalid[i] = { ...valid[0], ...invalid[i] }
}

describe('AAAA record', function () {
  base.suite(AAAA, { typeId: 28, fields: ['address'], valid, invalid })

  it('imports a native tinydns 3 line', function () {
    assert.equal(
      AAAA.fromTinydns('3test.example.com:20010db80020000a0000000000000004:3600::\n').toBind(),
      valid[0].testB,
    )
  })

  it('accepts an embedded IPv4 address (RFC 4291 §2.2)', function () {
    const r = new AAAA({ owner: 'a.example.', ttl: 60, address: '::ffff:192.0.2.1' })
    assert.equal(r.get('address'), '0000:0000:0000:0000:0000:ffff:c000:0201')
    assert.equal(AAAA.fromWire(r.toWire()).get('address'), r.get('address'))
  })
})
