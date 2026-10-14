import { test, describe } from 'node:test'
import assert from 'node:assert/strict'

import {
  encodeName,
  readWireName,
  decompressRdata,
  buildQuery,
  parseResponse,
  svcParamsFromWire,
  svcParamsToWire,
  wirePackDomain,
  wirePackDomainCompressed,
} from '../lib/wire.js'

const hex = (bytes) => Buffer.from(bytes).toString('hex')
const bytes = (h) => Buffer.from(h, 'hex')
const label63 = `3f${'61'.repeat(63)}`

test('encodeName', () => {
  for (const [name, expected] of [
    ['example.', '076578616d706c6500'],
    ['example', '076578616d706c6500'],
    ['www.example.com.', '03777777076578616d706c6503636f6d00'],
    ['.', '00'],
  ]) {
    assert.equal(hex(encodeName(name)), expected, name)
  }
})

describe('readWireName', () => {
  test('reads plain and pointer-compressed names', () => {
    for (const [packet, offset, name, end] of [
      ['03666f6f0362617200', 0, '03666f6f0362617200', 9],
      ['03666f6f00c000', 5, '03666f6f00', 7],
      ['03626172000362617a00c000', 10, '0362617200', 12],
    ]) {
      const r = readWireName(bytes(packet), offset)
      assert.deepEqual([hex(r.bytes), r.end], [name, end], packet)
    }
  })

  test('rejects malformed names', () => {
    // 200 pointers, each to the next, ending in a root label
    const chain = Buffer.alloc(401)
    for (let i = 0; i < 200; i++) chain.writeUInt16BE(0xc000 | ((i + 1) * 2), i * 2)

    for (const [packet, msg, offset = 0] of [
      ['c000', /pointer cycle detected/],
      ['c002c000', /pointer cycle detected/],
      [hex(chain), /pointer chain too long/],
      [`${label63.repeat(5)}00`, /name exceeds 255 bytes/],
      // RFC 1035 §3.1: 4 × 64 octets is 256 before the terminator
      [`${label63.repeat(4)}00`, /name exceeds 255 bytes/],
      ['c0', /truncated pointer/],
      ['c080', /pointer target out of bounds/],
      ['056161', /truncated label/],
      ['026161', /unterminated name/],
      ['400000', /reserved label type/], // RFC 1035 §4.1.4
      ['00', /offset out of bounds/, 5],
    ]) {
      assert.throws(() => readWireName(bytes(packet), offset), msg, packet.slice(0, 20))
    }
  })
})

test('wirePackDomainCompressed points at earlier names', () => {
  const dict = new Map()
  const first = wirePackDomainCompressed('www.example.com.', dict, 12)
  assert.equal(hex(first), hex(wirePackDomain('www.example.com.')))
  // example.com. starts after \x03www, at 16
  assert.equal(hex(wirePackDomainCompressed('mail.example.com.', dict, 12 + first.length)), '046d61696cc010')
  assert.equal(hex(wirePackDomainCompressed('www.example.com.', dict, 50)), 'c00c')
  assert.equal(hex(wirePackDomainCompressed('.', new Map([['.', 0]]), 50)), '00')

  const d2 = new Map()
  const a = wirePackDomainCompressed('foo.example.com.', d2, 0)
  const packet = Buffer.concat([a, wirePackDomainCompressed('bar.example.com.', d2, a.length)])
  assert.equal(hex(readWireName(packet, a.length).bytes), hex(wirePackDomain('bar.example.com.')))
})

test('decompressRdata copies rdata with inline names by type', () => {
  for (const [typeId, rdata] of [
    [99, '01020304'], // unknown: raw slice
    [2, '036e733100'], // NS
    [5, '04686f737400'], // CNAME
    [15, '000a046d61696c00'], // MX
    [33, '0001000000500377777700'], // SRV
    [6, `026e73000561646d696e00${'00'.repeat(20)}`], // SOA
    [17, '046d61696c000374787400'], // RP
    [35, '000000000155035349500000'], // NAPTR
  ]) {
    const packet = Buffer.concat([Buffer.alloc(12), bytes(rdata)])
    assert.equal(hex(decompressRdata(packet, 12, rdata.length / 2, typeId)), rdata, String(typeId))
  }
})

test('buildQuery writes one question, RD, and an OPT record', () => {
  const q = buildQuery('example.com', 1)
  const name = encodeName('example.com')
  assert.ok(Buffer.isBuffer(q))
  assert.equal((q.readUInt16BE(2) >> 8) & 1, 1, 'RD')
  assert.equal(q.readUInt16BE(4), 1, 'QDCOUNT')
  assert.equal(q.readUInt16BE(10), 1, 'ARCOUNT')
  assert.deepEqual(q.subarray(12, 12 + name.length), Buffer.from(name))
  assert.equal(q.readUInt16BE(12 + name.length + 4 + 1), 41, 'OPT type')
})

test('parseResponse', () => {
  const nxdomain = bytes('000083030000000000000000')
  assert.deepEqual(parseResponse(nxdomain), { rcode: 3, answers: [] })

  // header (QR, ANCOUNT=1) + root A IN ttl 300 rdata 1.2.3.4
  const { rcode, answers } = parseResponse(
    bytes('000080000000000100000000' + '00000100010000012c000401020304'),
  )
  assert.equal(rcode, 0)
  assert.equal(answers.length, 1)
  assert.equal(answers[0].typeId, 1)
  assert.equal(answers[0].cls, 1)
  assert.equal(hex(answers[0].rdataBytes), '01020304')
})

describe('svcParams (RFC 9460)', () => {
  test('encodes params sorted by key, with escapes decoded as BIND does (Appendix A.1)', () => {
    for (const [params, expected] of [
      ['', ''],
      [null, ''],
      [undefined, ''],
      ['no-default-alpn', '00020000'],
      ['port=8443', '0003000220fb'],
      ['alpn="h2,h3"', '00010006026832026833'],
      ['ipv4hint=1.2.3.4', '0004000401020304'],
      ['ipv4hint=1.2.3.4,5.6.7.8', '000400080102030405060708'],
      ['ipv6hint=::1', `00060010${'00'.repeat(15)}01`],
      ['port=443 alpn="h2"', '000100030268320003000201bb'],
      ['mandatory=port,alpn alpn=h2 port=443', '0000000400010003000100030268320003000201bb'],
      ['key1234=te\\032st', '04d200057465207374'],
      ['alpn=h2\\,draft', '00010009026832056472616674'],
      ['alpn=h2\\\\,draft', '000100090868322c6472616674'],
      ['alpn="f\\\\\\\\oo\\\\,bar,h2"', '0001000c08665c6f6f2c626172026832'],
      ['key1234="a\\"b"', '04d20003612262'],
      ['key1234=a\\ b', '04d20003612062'],
    ]) {
      const wire = svcParamsToWire(params)
      assert.ok(wire instanceof Uint8Array)
      assert.equal(hex(wire), expected, params)
      assert.deepEqual(svcParamsToWire(svcParamsFromWire(wire)), wire, `${params} round trips`)
    }
  })

  test('keyNNNN and mandatory round trip through wire', () => {
    for (const params of ['key1234=test', 'key65000=a\\032b', 'mandatory=alpn,key9 alpn="h2" key9=x']) {
      assert.equal(svcParamsFromWire(svcParamsToWire(params)), params)
    }
  })

  test('rejects values the encoder would otherwise coerce (§7)', () => {
    for (const [params, msg] of [
      ['unknownkey=foo', /unknown SvcParamKey: unknownkey/], // §2.1
      ['port=bogus', /port must be 0-65535/],
      ['port=65536', /port must be 0-65535/],
      ['ipv4hint=999.2.3.4', /invalid IPv4 address/],
      ['ipv6hint=::1::2', /invalid IPv6 address/],
      ['alpn=h2 alpn=h3', /duplicate SvcParamKey/],
      ['mandatory=mandatory', /may not list itself/],
      ['no-default-alpn=x', /takes no value/],
      ['key65535=x', /reserved/],
      ['ech=AQ', /ech must be base64/],
      ['alpn="h2', /unterminated quoted value for alpn/],
      ['alpn="h2"x', /text after the quoted value of alpn/],
      [`key9=${'a'.repeat(65536)}`, /over 65535/],
    ]) {
      assert.throws(() => svcParamsToWire(params), msg, params.slice(0, 30))
    }
  })

  test('tokenizes in linear time', () => {
    const start = Date.now()
    assert.throws(() => svcParamsToWire(`${'!='.repeat(50000)}!`), /unknown SvcParamKey/)
    assert.ok(Date.now() - start < 1000)
  })

  test('decoder rejects malformed params instead of truncating them', () => {
    for (const [wire, msg] of [
      ['000300', /inside a key header/],
      ['0003000500', /value is truncated/],
      ['00030003000102', /invalid length 3/],
      ['000300021f40000100020268', /out of order or repeated/],
      ['0001000303683200', /malformed alpn/],
      ['0000000400030001', /mandatory key 1 is out of order/],
      ['0000000400010001', /mandatory key 1 is out of order or repeated/],
    ]) {
      assert.throws(() => svcParamsFromWire(bytes(wire)), msg, wire)
    }
  })
})
