import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import LOC from '../../rr/loc.js'

const valid = [
  {
    owner: 'loc.home.example.com.',
    address: '47 43 47 N 122 21 35 W 132m 100m 100m 2m',
    testB: `loc.home.example.com.\t3600\tIN\tLOC\t47 43 47 N 122 21 35 W 132m 100m 100m 2m\n`,
    testT: ':loc.home.example.com:29:\\000\\024\\024"\\212=\\3378e\\276\\224h\\000\\230\\312\\020:3600::\n',
  },
  {
    owner: 'cambridge-net.kei.com.',
    address: '42 21 54 N 71 6 18 W -24m 30m',
    testB: 'cambridge-net.kei.com.\t3600\tIN\tLOC\t42 21 54 N 71 6 18 W -24m 30m\n',
    testT:
      ':cambridge-net.kei.com:29:\\0003\\026\\023\\211\\027-\\320p\\276\\025\\360\\000\\230\\215 :3600::\n',
  },
  {
    owner: 'rwy04l.logan-airport.boston.',
    address: '42 21 28.764 N 71 0 51.617 W -44m 2000m',
    testB: 'rwy04l.logan-airport.boston.\t3600\tIN\tLOC\t42 21 28.764 N 71 0 51.617 W -44m 2000m\n',
    testT:
      ':rwy04l.logan-airport.boston:29:\\000%\\026\\023\\211\\026\\313<p\\303\\020\\337\\000\\230\\205P:3600::\n',
  },
  {
    owner: 'loc.nictool.tnpi.net.',
    address: '37 46 39 N 122 25 9 W 16m',
    testB: 'loc.nictool.tnpi.net.\t3600\tIN\tLOC\t37 46 39 N 122 25 9 W 16m\n',
    testT:
      ':loc.nictool.tnpi.net:29:\\000\\022\\026\\023\\210\\033.\\030e\\273Px\\000\\230\\234\\300:3600::\n',
    testW: '036c6f63076e6963746f6f6c04746e7069036e657400001d000100000e10001000121613881b2e1865bb507800989cc0',
  },
]

const invalid = [
  {
    owner: 'server.example.com.',
    address: '', // empty
    msg: /address is required/,
  },
]

describe('LOC record', function () {
  base.suite(LOC, { typeId: 29, fields: ['address'], valid, invalid })

  const loc = (address) => new LOC({ owner: 'a.example.', ttl: 60, address })
  const fromRdata = (rdata) => new LOC(null).fromWire({ owner: 'a.example.', cls: 'IN', ttl: 60, rdata })

  it('converts SIZE/PREC to and from exponent format', function () {
    const r = loc(valid[0].address)
    assert.equal(r.toExponent(100), 18)
    assert.equal(r.fromExponent(18), 100)
    assert.throws(() => r.arcSecToDMS(1000000, 'neither'), /unknown or missing hemisphere/)
  })

  it('encodes omitted size and precision as 1m, 10000m and 10m (RFC 1876 §2)', function () {
    const r = loc('42 21 54 N 71 6 18 W -24m')
    assert.deepEqual([...r.getWireRdata().subarray(1, 4)], [0x12, 0x16, 0x13])
    assert.equal(LOC.fromWire(r.toWire()).get('address'), '42 21 54 N 71 6 18 W -24m')
  })

  it('keeps millisecond seconds through the wire (RFC 1876 §3)', function () {
    for (const address of ['42 21 54.005 N 71 6 18 W -24m', '42 21 32.123 N 71 6 18.3 W -24.07m']) {
      const r = loc(address)
      assert.deepEqual(LOC.fromWire(r.toWire()).getWireRdata(), r.getWireRdata(), address)
    }
  })

  it('rejects invalid input', function () {
    for (const address of [
      '91 0 0 N 0 0 0 E 0m',
      '0 0 0 N 181 0 0 E 0m',
      '0 60 0 N 0 0 0 E 0m',
      '0 0 0 N 0 0 0 E -100001m',
    ]) {
      assert.throws(() => loc(address), /out of range/, address)
    }
    for (const address of [
      '. 0 0 N 0 0 0 E 0m',
      '0 0 1..2 N 0 0 0 E 0m',
      '0 0 0 N 0 0 0 E .m',
      '0 0 0 N 0 0 0 E 0m 1..2m',
    ]) {
      assert.throws(() => loc(address), /LOC address: invalid format/, address)
    }
    for (const [offset, octet, msg] of [
      [0, 1, /version 0/],
      [1, 0xa2, /nibble over 9/],
      [2, 0x1f, /nibble over 9/],
    ]) {
      const rdata = loc(valid[0].address).getWireRdata()
      rdata[offset] = octet
      assert.throws(() => fromRdata(rdata), msg, `${offset}: ${octet}`)
    }
    assert.throws(
      () => LOC.fromBind('a.example. 60 IN LOC 42 21 54 N 71 6 18 W -24m trailing'),
      /LOC address: invalid format/,
    )
  })
})
