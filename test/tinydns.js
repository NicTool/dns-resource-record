import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as TINYDNS from '../lib/tinydns.js'
import CAA from '../rr/caa.js'
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
