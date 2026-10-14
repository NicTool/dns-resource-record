import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import UNKNOWN from '../../rr/unknown.js'
import A from '../../rr/a.js'
import MX from '../../rr/mx.js'
import TXT from '../../rr/txt.js'
import * as INDEX from '../../index.js'
import * as base from '../base.js'

// F1/F2 are the RFC 3597 §5 worked examples; F4 exercises the octets that
// break naive escaping (NUL, colon, backslash, non-ASCII)
const valid = [
  {
    owner: 'a.example.',
    ttl: 3600,
    class: 'CLASS32',
    type: 'TYPE731',
    rdata: 'abcdef012345',
    testB: 'a.example.\t3600\tCLASS32\tTYPE731\t\\# 6 abcdef012345\n',
    testW: '0161076578616d706c650002db002000000e100006abcdef012345',
  },
  {
    owner: 'b.example.',
    ttl: 3600,
    class: 'HS',
    type: 'TYPE62347',
    rdata: '',
    testB: 'b.example.\t3600\tHS\tTYPE62347\t\\# 0\n',
    testW: '0162076578616d706c6500f38b000400000e100000',
  },
  {
    owner: 'unknown.example.com.',
    ttl: 3600,
    type: 'TYPE65280',
    rdata: '0a000001',
    testB: 'unknown.example.com.\t3600\tIN\tTYPE65280\t\\# 4 0a000001\n',
    testT: ':unknown.example.com:65280:\\012\\000\\000\\001:3600::\n',
    testW: '07756e6b6e6f776e076578616d706c6503636f6d00ff00000100000e1000040a000001',
  },
  {
    owner: 'codec.example.com.',
    ttl: 3600,
    type: 'TYPE65281',
    rdata: '003a5c80ff',
    testB: 'codec.example.com.\t3600\tIN\tTYPE65281\t\\# 5 003a5c80ff\n',
    testT: ':codec.example.com:65281:\\000\\072\\134\\200\\377:3600::\n',
    testW: '05636f646563076578616d706c6503636f6d00ff01000100000e100005003a5c80ff',
  },
]

const invalid = [
  { ...valid[2], type: 'TYPE70000', msg: /invalid DNS type/ },
  { ...valid[2], type: 'BOGUS', msg: /invalid DNS type/ },
  { ...valid[2], type: undefined, msg: /type is required/ },
  { ...valid[2], rdata: 'abc', msg: /even-length hex/ },
  { ...valid[2], rdata: 'zz', msg: /even-length hex/ },
  { ...valid[2], rdata: undefined, msg: /rdata is required/ },
  { ...valid[2], class: 'CLASS99999', msg: /invalid class/ },
  { tinyline: ':x.example.com:70000:\\012:3600::\n', msg: /invalid tinydns type id/ },
  { tinyline: ':x.example.com:1x:\\012:3600::\n', msg: /invalid tinydns type id/ },
  { tinyline: ':x.example.com::\\012:3600::\n', msg: /invalid tinydns type id/ },
  { tinyline: ':x.example.com:-1:\\012:3600::\n', msg: /invalid tinydns type id/ },
  { bindline: 'x.example. 3600 IN TYPE731 \\# 3 abcdef01', msg: /length mismatch/ },
  { bindline: 'x.example. 3600 IN TYPE731 \\# 0 aa', msg: /length mismatch/ },
  { bindline: 'x.example. 3600 IN TYPE731 \\# 1 gg', msg: /even number of hex digits/ },
  { bindline: 'x.example. 3600 IN TYPE731 \\# 1 a b', msg: /even number of hex digits/ },
  { bindline: 'x.example. 3600 IN TYPE731 \\# 1x aa', msg: /invalid rdata length/ },
  { bindline: 'x.example. 3600 IN TYPE731 \\# -1 aa', msg: /invalid rdata length/ },
  { bindline: 'x.example. 3600 IN TYPE731 \\# 70000 aa', msg: /invalid rdata length/ },
  { bindline: 'x.example. 3600 IN TYPE731 1.2.3.4', msg: /generic form/ },
]

describe('UNKNOWN record', function () {
  base.suite(UNKNOWN, { fields: ['rdata'], valid, invalid })

  // RFC 3597 §5
  it('reads known types in generic form', function () {
    for (const [Type, line, expected] of [
      [A, 'e.example. 86400 IN A \\# 4 0a000001', { address: '10.0.0.1' }],
      [A, 'e.example. 86400 IN A \\# 4 ( 0A 00 00 01 )', { address: '10.0.0.1' }],
      [
        MX,
        'f.example. 3600 IN MX \\# 16 000a046d61696c076578616d706c6500',
        { preference: 10, exchange: 'mail.example.' },
      ],
      [A, 'e.example. 86400 CLASS1 TYPE1 10.0.0.2', { class: 'IN', address: '10.0.0.2' }],
      [UNKNOWN, 'x.example. 3600 IN AFSDB \\# 0', { type: 'TYPE18', rdata: '' }],
    ]) {
      const r = Type.fromBind(line)
      assert.ok(r instanceof Type, line)
      for (const [k, v] of Object.entries(expected)) assert.equal(r.get(k), v, line)
    }
  })

  it('rejects generic rdata it cannot convert losslessly', function () {
    for (const [Type, line, msg] of [
      // this library stores names lowercase and must not rewrite rdata (RFC 3597 §3)
      [MX, 'f.example. 3600 IN MX \\# 16 000a044d61496c076578616d706c6500', /cannot preserve rdata case/],
      [A, 'e.example. 3600 IN TYPE2 \\# 0', /TYPE2 does not match type id 1/],
      [A, 'e.example. 3600 IN BOGUS \\# 4 0a000001', /invalid DNS type/],
      [A, 'e.example. 3600 IN A \\# 5 0a000001ff', /A: 1 rdata bytes after the last field/],
      [MX, 'f.example. 3600 IN MX \\# 3 000a04', /wire label runs past the end/],
    ]) {
      assert.throws(() => Type.fromBind(line), msg, line)
    }
  })

  it('takes its type id from the instance', function () {
    assert.equal(new UNKNOWN(valid[0]).getTypeId(), 731)
    assert.throws(() => new UNKNOWN(null).getTypeId(), /type is not set/)
    const r = new UNKNOWN({ ...valid[2], type: undefined, typeId: 65280 })
    assert.equal(r.get('type'), 'TYPE65280')
    // classFor('AFSDB') falls back to UNKNOWN, so UNKNOWN must consume the mnemonics that sent it there
    assert.equal(new UNKNOWN({ ...valid[2], type: 'AFSDB' }).get('type'), 'TYPE18')
  })

  it('classFor resolves mnemonics and ids', function () {
    for (const [type, Type] of [
      ['MX', INDEX.MX],
      ['TYPE1', INDEX.A],
      [16, INDEX.TXT],
      [731, INDEX.UNKNOWN],
      ['TYPE65280', INDEX.UNKNOWN],
      ['AFSDB', INDEX.UNKNOWN],
    ]) {
      assert.equal(INDEX.classFor(type), Type, type)
    }
    assert.throws(() => INDEX.classFor('BOGUS'), /invalid DNS type/)
  })

  it('converts to and from a concrete RR', function () {
    const a = new A({ owner: 'e.example.', ttl: 3600, address: '10.0.0.1' })
    const u = UNKNOWN.fromRR(a)
    assert.equal(u.toBind(), 'e.example.\t3600\tIN\tTYPE1\t\\# 4 0a000001\n')
    assert.equal(u.toRR(A).get('address'), '10.0.0.1')
    assert.throws(() => u.toRR(TXT), /does not match TXT/)
    const extra = new UNKNOWN({ owner: 'e.example.', ttl: 3600, typeId: 1, rdata: '0a000001ff' })
    assert.throws(() => extra.toRR(A), /1 rdata bytes after the last field/)
  })

  it('exports MaraDNS RAW with unquoted \\xNN rdata', function () {
    assert.equal(
      new UNKNOWN(valid[2]).toMaraDNS(),
      'unknown.example.com.\t+3600\tRAW 65280\t\\x0a\\x00\\x00\\x01 ~\n',
    )
    assert.equal(
      new UNKNOWN(valid[3]).toMaraDNS(),
      'codec.example.com.\t+3600\tRAW 65281\t\\x00\\x3a\\x5c\\x80\\xff ~\n',
    )
    const empty = new UNKNOWN({ owner: 'b.example.', ttl: 3600, typeId: 62347, rdata: '' })
    assert.equal(empty.toMaraDNS(), "b.example.\t+3600\tRAW 62347\t'' ~\n")
  })

  it('refuses tinydns and MaraDNS for non-IN classes', function () {
    assert.throws(() => new UNKNOWN(valid[0]).toTinydns(), /only class IN/)
    assert.throws(() => new UNKNOWN(valid[0]).toMaraDNS(), /only class IN/)
  })
})
