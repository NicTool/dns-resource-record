import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as TINYDNS from '../lib/tinydns.js'
import A from '../rr/a.js'
import CAA from '../rr/caa.js'
import CNAME from '../rr/cname.js'
import HINFO from '../rr/hinfo.js'
import SRV from '../rr/srv.js'
import TXT from '../rr/txt.js'

describe('TINYDNS', function () {
  it('escapes only the octets that are unprintable or end or escape a field', function () {
    assert.equal(
      TINYDNS.bytesToTinydnsText(Uint8Array.from([0x61, 0x20, 0x3a, 0x5c, 0x7f, 0x00, 0xff])),
      'a \\072\\134\\177\\000\\377',
    )
  })

  for (const target of ['a\\.b.example.', 'sp\\032ace.example.', 'x\\195\\169.example.']) {
    it(`round trips an escaped name through a generic line: ${target}`, function () {
      const r = new SRV({ owner: '_x._tcp.example.', ttl: 60, priority: 1, weight: 2, port: 3, target })
      assert.equal(SRV.fromTinydns(r.toTinydns()).get('target'), target)
    })
  }

  // djbdns reads \ooo in a name as octal, and ':' ends a field; verified
  // against tinydns-data and tinydns-get
  it('writes and reads names with djbdns escapes', function () {
    for (const [owner, tinydns, imported = owner] of [
      ['sp\\032ace.example.', 'sp\\040ace.example'],
      ['co\\058lon.example.', 'co\\072lon.example'],
      ['a\\.b.example.', 'a\\.b.example'],
      ['a\\046b.example.', 'a\\056b.example', 'a\\.b.example.'],
      ['x\\195\\169.example.', 'x\\303\\251.example'],
      ['école.example.', 'école.example'],
      ['back\\\\slash.example.', 'back\\134slash.example', 'back\\092slash.example.'],
      ['st\\042ar.example.', 'st\\052ar.example'],
      ['*.w.example.', '*.w.example'],
      ['ctl\\001.example.', 'ctl\\001.example'],
      ['host\\..', 'host\\.'],
    ]) {
      const a = new A({ owner, ttl: 60, address: '192.0.2.1' })
      assert.equal(a.toTinydns(), `+${tinydns}:192.0.2.1:60::\n`)
      assert.equal(A.fromTinydns(a.toTinydns()).get('owner'), imported)
      const cname = new CNAME({ owner: 'c.example.', ttl: 60, cname: owner })
      assert.equal(CNAME.fromTinydns(cname.toTinydns()).get('cname'), imported)
    }
    // \X is X, and a short octal escape is still octal
    assert.equal(A.fromTinydns('+a\\;b\\40c.example:192.0.2.1:60::').get('owner'), 'a\\059b\\032c.example.')
  })

  it('rejects a TXT line with no fields as invalid, not with a crash', function () {
    assert.throws(() => TXT.fromTinydns("'x.example"), { name: 'Error' })
  })

  it('reads text between octal escapes as UTF-8, as tinydns-data does', function () {
    assert.deepEqual([...TINYDNS.octalRdataToBytes('caf\u00e9\\041')], [0x63, 0x61, 0x66, 0xc3, 0xa9, 0x21])
    assert.equal(TXT.fromTinydns("'x.example:caf\u00e9:60::").get('data'), 'caf\u00e9')
  })

  describe('generic character-string rdata', function () {
    for (const [C, line] of [
      [TXT, ':x:16:\\001\\377:60::'],
      [HINFO, ':x:13:\\001\\377\\001a:60::'],
      [CAA, ':x:257:\\000\\005issue\\377:60::'],
    ]) {
      it(`rejects ${C.typeName} octets that are not UTF-8`, function () {
        assert.throws(() => C.fromTinydns(line), /is not UTF-8/)
      })
    }

    for (const r of [
      new CAA({ owner: 'x.', ttl: 60, flags: 0, tag: 'issue', value: 'é.example' }),
      new HINFO({ owner: 'x.', ttl: 60, cpu: 'é', os: 'a' }),
    ]) {
      it(`round trips UTF-8 ${r.get('type')} rdata byte for byte`, function () {
        assert.deepEqual(r.constructor.fromTinydns(r.toTinydns()).getWireRdata(), r.getWireRdata())
      })
    }
  })
})
