import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { bytesToHex } from '../lib/binary.js'

// TXT data may be one string or its character-strings (RFC 1035 §3.3.14).
const flat = (v) => (Array.isArray(v) ? v.join('') : v)

function assertSameRecord(actual, expected, skip = []) {
  for (const f of expected.getFields()) {
    if (!skip.includes(f)) assert.deepEqual(flat(actual.get(f)), flat(expected.get(f)), f)
  }
}

/**
 * The checks every RR type shares. Each valid record must store its fields as
 * given, and match its testB (BIND), testT (tinydns) and testW (wire hex)
 * fixtures in both directions. Each invalid record must throw its msg.
 * Records without a ttl get 3600.
 */
export function suite(Type, { typeId, fields, valid = [], invalid = [] }) {
  const callSite = new Error()
  const withTtl = (rec) => ({ ttl: 3600, ...rec })

  it('describes itself', function () {
    const r = new Type(null)
    if (typeId !== undefined) assert.equal(r.getTypeId(), typeId)
    if (fields) assert.deepEqual(r.getFields(), [...r.getFields('common'), ...fields])
    assert.ok(r.getDescription())
    assert.ok(r.getRFCs().length)
    assert.ok(Array.isArray(r.getTags()))
    assert.ok(new Type(r.getCanonical()))
  })

  for (const rec of valid.map(withTtl)) {
    describe(rec.owner, function () {
      it('stores each field', function () {
        const r = new Type(rec)
        for (const [k, v] of Object.entries(rec)) {
          if (!k.startsWith('test')) assert.deepEqual(r.get(k), v, k)
        }
      })

      if (rec.testB !== undefined) {
        it('BIND', function () {
          const r = new Type(rec)
          assert.equal(r.toBind(), rec.testB)
          assertSameRecord(Type.fromBind(rec.testB), r)
        })
      }

      if (rec.testT !== undefined) {
        it('tinydns', function () {
          const r = new Type(rec)
          // tinydns serves only class IN
          if (r.get('class') === 'IN') assert.equal(r.toTinydns(), rec.testT)
          assertSameRecord(Type.fromTinydns(rec.testT), r, ['class'])
        })
      }

      it('wire', function () {
        const wire = new Type(rec).toWire()
        if (rec.testW) assert.equal(bytesToHex(wire), rec.testW)
        assert.deepEqual(Type.fromWire(wire).toWire(), wire)
      })
    })
  }

  for (const inv of invalid) {
    it(`rejects ${inv.owner ?? inv.bindline ?? inv.tinyline}`, function () {
      try {
        if (inv.bindline !== undefined) assert.throws(() => Type.fromBind(inv.bindline), { message: inv.msg })
        else if (inv.tinyline !== undefined)
          assert.throws(() => Type.fromTinydns(inv.tinyline), { message: inv.msg })
        else assert.throws(() => new Type(withTtl(inv)), { message: inv.msg })
      } catch (e) {
        e.stack = `${e.message}\n${callSite.stack.split('\n').slice(1).join('\n')}`
        throw e
      }
    })
  }
}
