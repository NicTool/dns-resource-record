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
const validRecords = [
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
    class: 'IN',
    type: 'TYPE65280',
    rdata: '0a000001',
    testB: 'unknown.example.com.\t3600\tIN\tTYPE65280\t\\# 4 0a000001\n',
    testT: ':unknown.example.com:65280:\\012\\000\\000\\001:3600::\n',
    testW: '07756e6b6e6f776e076578616d706c6503636f6d00ff00000100000e1000040a000001',
  },
  {
    owner: 'codec.example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'TYPE65281',
    rdata: '003a5c80ff',
    testB: 'codec.example.com.\t3600\tIN\tTYPE65281\t\\# 5 003a5c80ff\n',
    testT: ':codec.example.com:65281:\\000\\072\\134\\200\\377:3600::\n',
    testW: '05636f646563076578616d706c6503636f6d00ff01000100000e100005003a5c80ff',
  },
]

const invalidRecords = [
  { ...validRecords[2], type: 'TYPE70000', msg: /TYPE<0-65535>/ },
  { ...validRecords[2], type: 'A', msg: /TYPE<0-65535>/ },
  { ...validRecords[2], type: undefined, msg: /TYPE<0-65535>/ },
  { ...validRecords[2], rdata: 'abc', msg: /even-length hex/ },
  { ...validRecords[2], rdata: 'zz', msg: /even-length hex/ },
  { ...validRecords[2], rdata: undefined, msg: /rdata is required/ },
  { ...validRecords[2], class: 'CLASS99999', msg: /invalid class/ },
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
  base.valid(UNKNOWN, validRecords)
  base.invalid(UNKNOWN, invalidRecords)

  base.getDescription(UNKNOWN)
  base.getRFCs(UNKNOWN, validRecords[0])
  base.getRdataFields(UNKNOWN, ['rdata'])
  base.getFields(UNKNOWN, ['rdata'])
  base.getCanonical(UNKNOWN)
  base.getTags(UNKNOWN)

  base.toBind(UNKNOWN, validRecords)
  base.toWire(UNKNOWN, validRecords)
  base.toTinydns(UNKNOWN, validRecords)

  base.fromBind(UNKNOWN, validRecords)
  base.fromTinydns(UNKNOWN, validRecords)
  base.fromWire(UNKNOWN, validRecords)

  describe('known types in generic form (RFC 3597 §5)', function () {
    it('converts generic rdata to the concrete class', function () {
      const a = A.fromBind('e.example. 86400 IN A \\# 4 0a000001')
      assert.ok(a instanceof A)
      assert.equal(a.get('address'), '10.0.0.1')
    })

    it('accepts parenthesized continuations and uppercase hex', function () {
      const a = A.fromBind('e.example. 86400 IN A \\# 4 ( 0A 00 00 01 )')
      assert.equal(a.get('address'), '10.0.0.1')
    })

    it('decodes rdata with an embedded domain name', function () {
      const mx = MX.fromBind('f.example. 3600 IN MX \\# 16 000a046d61696c076578616d706c6500')
      assert.equal(mx.get('preference'), 10)
      assert.equal(mx.get('exchange'), 'mail.example.')
    })

    it('parses TYPE1/CLASS1 mnemonics with native rdata', function () {
      const a = A.fromBind('e.example. 86400 CLASS1 TYPE1 10.0.0.2')
      assert.equal(a.get('class'), 'IN')
      assert.equal(a.get('address'), '10.0.0.2')
    })

    it('throws on a TYPEnnn / class mismatch', function () {
      assert.throws(() => A.fromBind('e.example. 3600 IN TYPE2 \\# 0'), /TYPE2 does not match type id 1/)
    })

    it('throws when rdata has extra bytes (no lossy acceptance)', function () {
      assert.throws(() => A.fromBind('e.example. 3600 IN A \\# 5 0a000001ff'))
    })

    it('throws when rdata is truncated mid-name', function () {
      assert.throws(() => MX.fromBind('f.example. 3600 IN MX \\# 3 000a04'))
    })
  })

  describe('getTypeId', function () {
    // the id lives on the instance, so base.getTypeId (static) does not apply
    it('parses the numeric id from the instance type', function () {
      assert.equal(new UNKNOWN(validRecords[0]).getTypeId(), 731)
    })

    it('throws when type is not set', function () {
      assert.throws(() => new UNKNOWN(null).getTypeId(), /type is not set/)
    })
  })

  describe('typeId constructor option', function () {
    it('accepts { typeId: 65280 } as TYPE65280', function () {
      const r = new UNKNOWN({ ...validRecords[2], type: undefined, typeId: 65280 })
      assert.equal(r.get('type'), 'TYPE65280')
      assert.equal(r.getTypeId(), 65280)
    })
  })

  describe('toTinydns class guard', function () {
    it('throws for non-IN classes', function () {
      assert.throws(() => new UNKNOWN(validRecords[0]).toTinydns(), /only class IN/)
    })
  })

  describe('classFor', function () {
    it('resolves implemented mnemonics and ids to their class', function () {
      assert.equal(INDEX.classFor('MX'), INDEX.MX)
      assert.equal(INDEX.classFor('TYPE1'), INDEX.A)
      assert.equal(INDEX.classFor(16), INDEX.TXT)
    })

    it('resolves unimplemented types to UNKNOWN', function () {
      assert.equal(INDEX.classFor(731), INDEX.UNKNOWN)
      assert.equal(INDEX.classFor('TYPE65280'), INDEX.UNKNOWN)
      assert.equal(INDEX.classFor('AFSDB'), INDEX.UNKNOWN)
    })

    it('throws on unresolvable names', function () {
      assert.throws(() => INDEX.classFor('BOGUS'), /invalid DNS type/)
    })
  })

  describe('fromRR / toRR', function () {
    const a = new A({ owner: 'e.example.', ttl: 3600, class: 'IN', type: 'A', address: '10.0.0.1' })

    it('fromRR converts a known RR to its generic representation', function () {
      const u = UNKNOWN.fromRR(a)
      assert.equal(u.get('type'), 'TYPE1')
      assert.equal(u.get('rdata'), '0a000001')
      assert.equal(u.toBind(), 'e.example.\t3600\tIN\tTYPE1\t\\# 4 0a000001\n')
    })

    it('toRR converts back to the concrete class', function () {
      const back = UNKNOWN.fromRR(a).toRR(A)
      assert.ok(back instanceof A)
      assert.equal(back.get('address'), '10.0.0.1')
    })

    it('toRR throws on a type id mismatch', function () {
      assert.throws(() => UNKNOWN.fromRR(a).toRR(TXT), /does not match TXT/)
    })

    it('toRR throws when rdata does not round-trip (RFC 3597 §5)', function () {
      const extra = new UNKNOWN({ owner: 'e.example.', ttl: 3600, typeId: 1, rdata: '0a000001ff' })
      assert.throws(() => extra.toRR(A), /does not round-trip/)
    })
  })

  describe('cross-format round-trip', function () {
    it('tinydns -> wire -> instance preserves the record', function () {
      const orig = new UNKNOWN(validRecords[3])
      const viaTiny = UNKNOWN.fromTinydns(orig.toTinydns())
      assert.equal(viaTiny.toBind(), orig.toBind())
      assert.equal(viaTiny.toTinydns(), orig.toTinydns())
      const viaWire = UNKNOWN.fromWire(orig.toWire())
      assert.equal(viaWire.get('rdata'), orig.get('rdata'))
      assert.equal(viaWire.get('type'), orig.get('type'))
    })
  })
})
