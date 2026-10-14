import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import RR from '../rr.js'
import A from '../rr/a.js'
import DS from '../rr/ds.js'
import HINFO from '../rr/hinfo.js'
import KEY from '../rr/key.js'
import MX from '../rr/mx.js'
import SOA from '../rr/soa.js'
import SSHFP from '../rr/sshfp.js'
import TLSA from '../rr/tlsa.js'
import TXT from '../rr/txt.js'

const a = (opts) => new A({ owner: 'example.com.', ttl: 3600, address: '10.0.0.1', ...opts })

describe('RR', function () {
  const r = new RR(null)

  it('lists its fields', function () {
    assert.deepEqual(new RR(null).getFields(), ['owner', 'ttl', 'class', 'type'])
    assert.deepEqual(new A(null).getFields(), ['owner', 'ttl', 'class', 'type', 'address'])
  })

  it('setTtl accepts 0 to 2147483647 (RFC 2181 §8)', function () {
    for (const ttl of [-1, -299, 2147483648, undefined])
      assert.throws(() => r.setTtl(ttl), /TTL/, String(ttl))
    r.setTtl(2147483647)
    assert.equal(r.get('ttl'), 2147483647)
  })

  it('setClass accepts mnemonics and RFC 3597 §5 CLASSnnn', function () {
    for (const [input, expected] of [
      ['IN', 'IN'],
      ['CH', 'CH'],
      ['ANY', 'ANY'],
      ['NONE', 'NONE'],
      ['CLASS1', 'IN'],
      ['CLASS3', 'CH'],
      ['class4', 'HS'],
      ['CLASS32', 'CLASS32'],
      ['CLASS65535', 'CLASS65535'],
    ]) {
      r.setClass(input)
      assert.equal(r.get('class'), expected, input)
    }
    for (const bad of ['matt', 'CLASS99999', 0, 1])
      assert.throws(() => r.setClass(bad), /invalid class/, String(bad))
  })

  it('getClassId resolves mnemonics and CLASSnnn', function () {
    for (const [cls, id] of [
      ['IN', 1],
      ['HS', 4],
      ['CLASS32', 32],
    ]) {
      r.setClass(cls)
      assert.equal(r.getClassId(), id)
    }
  })

  it('checks integer widths', function () {
    for (const [bits, valid, invalid, max] of [
      [8, [1, 2, 255], [-1, 'a', new Date(), undefined, 256], 255],
      [16, [0, 1, 55555, 65535], ['a', new Date(), undefined, 65536], 65535],
      [32, [1, 55555, 4294967295], ['a', new Date(), undefined, 4294967296], 4294967295],
    ]) {
      const check = (v) => r[`is${bits}bitInt`]('test', 'field', v)
      for (const v of valid) assert.equal(check(v), true, `${bits}: ${v}`)
      for (const v of invalid)
        assert.throws(() => check(v), {
          message: `test field must be a ${bits}-bit integer (in the range 0-${max})`,
        })
    }
  })

  it('qualifies names', function () {
    assert.equal(r.fullyQualify(''), '')
    assert.equal(r.fullyQualify('example.com'), 'example.com.')
    assert.equal(r.isFullyQualified('$type', '$field', 'host.example.com.'), true)
    assert.throws(() => r.isFullyQualified('$type', '$field', 'host.example.com'), /must be fully qualified/)

    const rr = new RR(null)
    rr.set('owner', 'www.example.com') // bypass FQ check
    assert.equal(rr.getFQDN('owner'), 'www.example.com.')
    rr.setOwner('www.example.com.')
    assert.equal(rr.getFQDN('owner', { origin: 'example.com.', hide: { origin: true } }), 'www')

    for (const [value, expected] of [
      ['', ''],
      ['.', '.'],
    ]) {
      rr.set('target', value)
      assert.equal(rr.getTinyFQDN('target'), expected)
    }
  })

  it('isValidName accepts escapes and rejects unescaped delimiters (RFC 1035 §5.1)', function () {
    for (const n of [
      'x.',
      '2x.',
      '*.something.',
      'semi\\;colon.example.',
      'a\\032b.example.',
      'host@example.',
    ])
      assert.equal(r.isValidName('TEST', 'hostname', n), true, n)
    for (const n of [
      'semi;colon.example.',
      'a b.example.',
      'a"b.example.',
      '(a).example.',
      'nul\x00.example.',
      'del\x7f.example.',
    ])
      assert.throws(
        () => r.isValidName('TEST', 'hostname', n),
        /TEST: hostname has an unescaped delimiter/,
        n,
      )
    assert.throws(() => r.isValidName('TEST', 'hostname', `${'a'.repeat(64)}.example.`), /RFC 2181/)
  })

  it('quotes character-strings', function () {
    const hinfo = (cpu) => new HINFO({ owner: 'h.example.', ttl: 60, cpu, os: 'os' })
    assert.equal(hinfo('Intel x86').getQuoted('cpu'), "'Intel x86'")
    assert.equal(hinfo('"x"').getQuoted('cpu'), `'"x"'`)
    assert.equal(hinfo("'x").getQuoted('cpu'), "\\x27'x'")
    assert.equal(hinfo('x').getQuoted('owner'), 'h.example.')
    assert.equal(r.isQuoted('"yes, this is"'), true)
    assert.equal(r.isQuoted('nope, not quoted'), false)
  })

  it('compresses and expands IPv6 addresses', function () {
    for (const [expanded, compressed] of [
      ['2001:0db8:0020:000a:0000:0000:0000:0004', '2001:db8:20:a::4'],
      ['0000:0000:0000:0000:0000:0000:0000:0000', '::'],
      ['0000:0000:0000:0000:0000:0000:0000:0001', '::1'],
      ['2001:0db8:0000:0000:0000:0000:0002:0001', '2001:db8::2:1'],
      ['2001:0db8:0000:0001:0001:0001:0001:0001', '2001:db8:0:1:1:1:1:1'],
      ['2001:0db8:0000:0000:0008:0800:200c:417a', '2001:db8::8:800:200c:417a'],
    ]) {
      assert.equal(r.compressIPv6(expanded), compressed)
      assert.equal(r.expandIPv6(compressed), expanded)
    }
    assert.equal(r.isIPv6('::1'), true)
    assert.equal(r.isIPv6('::1\nnot an address'), false)
  })

  it('getWireRdata throws for a field the generic encoder has no type for', function () {
    class NOENC extends RR {
      static typeName = 'NOENC'
      static rdataFields = ['blob']
    }
    const r = new NOENC(null).set('blob', 'x')
    assert.throws(() => r.getWireRdata(), /NOENC: no generic wire encoder for blob \(untyped\)/)
  })

  it('getComment and getPrefix', function () {
    const rr = new RR(null)
    assert.equal(rr.getComment('owner'), '')
    rr.set('comment', { owner: 'test comment value' })
    assert.equal(rr.getComment('owner'), 'test comment value')
    assert.equal(rr.getComment('nonexistent'), '')
    const prefix = a().getPrefix({ hide: { sameOwner: true }, previousOwner: 'example.com.' })
    assert.equal(prefix, '\t3600\tIN\tA')
  })

  it('exports MaraDNS, falling back to RAW wire rdata', function () {
    assert.equal(a({ address: '1.2.3.4' }).toMaraDNS(), 'example.com.\t+3600\tA\t1.2.3.4 ~\n')
    const key = new KEY({
      owner: 'example.com.',
      ttl: 3600,
      flags: 256,
      protocol: 3,
      algorithm: 5,
      publickey: 'AQIDBA==',
    })
    assert.equal(key.toMaraDNS(), 'example.com.\t+3600\tRAW 25\t\\x01\\x00\\x03\\x05\\x01\\x02\\x03\\x04 ~\n')
  })

  // TXT, SOA and MX override the exporters, so the guard must hold there too
  it('refuses tinydns and MaraDNS exports of a non-IN class', function () {
    for (const rr of [
      a({ class: 'CH' }),
      new TXT({ owner: 'e.example.', ttl: 3600, class: 'CH', data: 'x' }),
      new MX({ owner: 'e.example.', ttl: 3600, class: 'CH', preference: 10, exchange: 'mail.example.' }),
      new SOA({ ...new SOA(null).getCanonical(), class: 'CH' }),
    ]) {
      assert.throws(() => rr.toTinydns(), /only class IN/, rr.get('type'))
      assert.throws(() => rr.toMaraDNS(), /only class IN/, rr.get('type'))
    }
  })

  it('fromWire checks lengths, type and class', function () {
    const wire = a().toWire()
    assert.equal(A.fromWire(wire).get('address'), '10.0.0.1')
    assert.throws(() => A.fromWire(new Uint8Array([...wire, 0xff])), /RDLENGTH/)
    assert.throws(() => A.fromWire(wire.slice(0, wire.length - 2)), /RDLENGTH/)
    assert.throws(() => A.fromWire(wire.slice(0, 20)), /truncated/)
    assert.throws(() => TXT.fromWire(wire), /wire type id 1 does not match 16/)
    assert.equal(A.fromWire(a({ class: 'CLASS32' }).toWire()).get('class'), 'CLASS32') // RFC 3597
  })

  it('fromBind keeps the class, takes a default TTL, and rejoins opaque rdata split across whitespace', function () {
    assert.equal(TXT.fromBind('version.bind. 0 CH TXT "9.18.1"').get('class'), 'CH')
    for (const line of ['a.example. IN A 192.0.2.1', 'a.example. IN A \\# 4 c0000201'])
      assert.equal(A.fromBind(line, { default: { ttl: 300 } }).get('ttl'), 300, line)
    assert.equal(A.fromBind('a.example. 60 IN A 192.0.2.1', { default: { ttl: 300 } }).get('ttl'), 60)
    // RFC 4034 §5.4 writes the digest in two whitespace separated halves
    const ds = DS.fromBind(
      'dskey.example.com. 86400 IN DS 60485 5 1 2BB183AF5F22588179A53B0A 98631FAD1A292118',
    )
    assert.equal(ds.get('digest'), '2BB183AF5F22588179A53B0A98631FAD1A292118')
  })
})

describe('isHexDigest', function () {
  const base = { owner: 'a.example.', ttl: 60 }

  it('checks digest length against the digest type', function () {
    const ds = (digestType, digest) =>
      new DS({ ...base, 'key tag': 1, algorithm: 13, 'digest type': digestType, digest })
    assert.throws(() => ds(1, 'ABCDEF123...'), /DS: digest must be hex octets/)
    assert.throws(() => ds(2, '2BB183AF5F22588179A53B0A98631FAD1A292118'), /must be 32 bytes, got 20/)
    assert.equal(ds(1, '2BB183AF5F22588179A53B0A98631FAD1A292118').get('digest type'), 1)

    const fp32 = 'ed8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26'
    assert.throws(
      () => new SSHFP({ ...base, algorithm: 1, fptype: 1, fingerprint: fp32 }),
      /must be 20 bytes, got 32/,
    )

    // TLSA matching type 0 takes any length
    const tlsa = (matchingType, data) =>
      new TLSA({
        ...base,
        'certificate usage': 3,
        selector: 1,
        'matching type': matchingType,
        'certificate association data': data,
      })
    assert.throws(() => tlsa(2, 'aabb'), /must be 64 bytes, got 2/)
    assert.equal(tlsa(0, 'aabb').get('matching type'), 0)
  })
})
