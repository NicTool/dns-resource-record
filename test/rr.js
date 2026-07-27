import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import RR from '../rr.js'
import A from '../rr/a.js'
import DS from '../rr/ds.js'
import KEY from '../rr/key.js'
import MX from '../rr/mx.js'
import SOA from '../rr/soa.js'
import TXT from '../rr/txt.js'

const cases = [
  // { name: 'RR class', obj: RR, expect: [ 'owner', 'ttl', 'class', 'type' ] },
  {
    name: 'RR instance',
    obj: new RR(null),
    expect: ['owner', 'ttl', 'class', 'type'],
  },
  // { name: 'A class', obj: A, expect: [ 'owner', 'ttl', 'class', 'type', 'address' ] },
  {
    name: 'A instance',
    obj: new A(null),
    expect: ['owner', 'ttl', 'class', 'type', 'address'],
  },
]

for (const c of cases) {
  describe(`${c.name}`, function () {
    describe('getFields', function () {
      it('gets expected fields', async function () {
        assert.deepEqual(c.obj.getFields(), c.expect)
      })
    })
  })
}

describe('RR', function () {
  const r = new RR(null)

  describe('setTtl', function () {
    const invalid = [-1, -4, -299, 2147483648, undefined]
    for (const i of invalid) {
      it(`throws on invalid TTL: ${i}`, async function () {
        try {
          assert.deepEqual(r.setTtl(i), false)
        } catch (e) {
          assert.ok(e.message)
          // console.error(e.message)
        }
      })
    }
  })

  describe('setClass', function () {
    for (const i of ['IN', 'CH', 'ANY', 'NONE']) {
      it(`accepts valid class: ${i}`, async function () {
        r.setClass(i)
        assert.deepEqual(r.get('class'), i)
      })
    }

    for (const i of ['matt', 'in', 0]) {
      it(`throws on invalid class: ${i}`, async function () {
        try {
          assert.equal(r.setClass(i), false)
        } catch (e) {
          assert.ok(e.message)
        }
      })
    }

    // RFC 3597 §5 CLASSnnn syntax
    for (const [input, expected] of [
      ['CLASS1', 'IN'],
      ['CLASS3', 'CH'],
      ['class4', 'HS'],
      ['CLASS32', 'CLASS32'],
      ['CLASS65535', 'CLASS65535'],
    ]) {
      it(`accepts generic class ${input} as ${expected}`, async function () {
        r.setClass(input)
        assert.equal(r.get('class'), expected)
      })
    }

    it('throws on out of range generic class: CLASS99999', async function () {
      assert.throws(() => r.setClass('CLASS99999'), /invalid class/)
    })
  })

  describe('getClassId', function () {
    for (const [cls, id] of [
      ['IN', 1],
      ['HS', 4],
      ['CLASS32', 32],
    ]) {
      it(`resolves ${cls} to ${id}`, async function () {
        r.setClass(cls)
        assert.equal(r.getClassId(), id)
      })
    }
  })

  describe('fullyQualify', function () {
    it('does nothing to empty  hostname', async () => {
      assert.equal(r.fullyQualify(''), '')
    })

    it('fully qualifies a valid hostname', async () => {
      assert.equal(r.fullyQualify('example.com'), 'example.com.')
    })
  })

  describe('getFQDN', function () {
    it('adds a period to hostnames', async () => {
      const rr = new RR(null)
      rr.set('owner', 'www.example.com') // bypass FQ check
      assert.equal(rr.getFQDN('owner'), 'www.example.com.')
    })

    it('reduces origin on request', async () => {
      const rr = new RR(null)
      const zone_opts = { origin: 'example.com.', hide: { origin: true } }
      rr.setOwner('www.example.com.')
      assert.equal(rr.getFQDN('owner', zone_opts), 'www')
    })
  })

  describe('isFullyQualified', function () {
    it('should detect FQDNs', async function () {
      assert.deepEqual(r.isFullyQualified('$type', '$field', 'host.example.com.'), true)

      try {
        assert.deepEqual(r.isFullyQualified('$type', '$field', 'host.example.com'), false)
      } catch (e) {
        assert.ok(/must be fully qualified/.test(e.message))
      }
    })
  })

  describe('is8bitInt', function () {
    const valid = [1, 2, 255]
    const invalid = [-1, 'a', new Date(), undefined, 256]

    for (const i of valid) {
      it(`returns true for valid int: ${i}`, async function () {
        assert.equal(r.is8bitInt('test', 'field', i), true)
      })
    }

    for (const i of invalid) {
      it(`throws on invalid int: ${i}`, async function () {
        try {
          assert.equal(r.is8bitInt('test', 'field', i), false)
        } catch (e) {
          assert.equal(e.message, 'test field must be a 8-bit integer (in the range 0-255)')
        }
      })
    }
  })

  describe('is16bitInt', function () {
    const valid = [0, 1, 2, 55555, 65535]
    const invalid = ['a', new Date(), undefined, 65536]

    for (const i of valid) {
      it(`returns true for valid int: ${i}`, async function () {
        assert.equal(r.is16bitInt('test', 'field', i), true)
      })
    }

    for (const i of invalid) {
      it(`throws on invalid int: ${i}`, async function () {
        try {
          assert.equal(r.is16bitInt('test', 'field', i), false)
        } catch (e) {
          assert.equal(e.message, 'test field must be a 16-bit integer (in the range 0-65535)')
        }
      })
    }
  })

  describe('is32bitInt', function () {
    const valid = [1, 2, 55555, 4294967295]
    const invalid = ['a', new Date(), undefined, 4294967296]

    for (const i of valid) {
      it(`returns true for valid int: ${i}`, async function () {
        assert.equal(r.is32bitInt('test', 'field', i), true)
      })
    }

    for (const i of invalid) {
      it(`throws on invalid int: ${i}`, async function () {
        try {
          assert.equal(r.is32bitInt('test', 'field', i), false)
        } catch (e) {
          assert.equal(e.message, 'test field must be a 32-bit integer (in the range 0-4294967295)')
        }
      })
    }
  })

  describe('getQuoted', function () {
    it('returns a quoted string', async () => {
      r.set('cpu', '"already quoted"')
      assert.equal(r.get('cpu'), '"already quoted"')
      assert.equal(r.getQuoted('cpu'), '"already quoted"') // doesn't double quote
    })

    it("doesn't double quote a quoted string", async () => {
      r.set('cpu', '"already quoted"')
      assert.equal(r.getQuoted('cpu'), '"already quoted"')
    })
  })

  describe('isQuoted', function () {
    it('detects a quoted strings', async function () {
      assert.deepEqual(r.isQuoted('"yes, this is"'), true)
    })

    it('detects non-quoted strings', async function () {
      assert.deepEqual(r.isQuoted('nope, not quoted'), false)
    })
  })

  describe('isValidHostname', function () {
    for (const n of ['x', '2x', '*', '*.something']) {
      it(`passes name: ${n}`, async function () {
        assert.deepEqual(r.isValidHostname(n), true)
      })
    }
  })

  const tests = [
    { e: '2001:0db8:0020:000a:0000:0000:0000:0004', c: '2001:db8:20:a::4' },
    { e: '0000:0000:0000:0000:0000:0000:0000:0000', c: '::' },
    { e: '0000:0000:0000:0000:0000:0000:0000:0001', c: '::1' },
    { e: '2001:0db8:0000:0000:0000:0000:0002:0001', c: '2001:db8::2:1' },
    { e: '2001:0db8:0000:0001:0001:0001:0001:0001', c: '2001:db8:0:1:1:1:1:1' },
    {
      e: '2001:0db8:0000:0000:0008:0800:200c:417a',
      c: '2001:db8::8:800:200c:417a',
    },
  ]

  describe('compressIPv6', function () {
    const r = new RR(null)
    for (const t of tests) {
      it(`compresses IPv6 address (${t.e})`, function () {
        assert.equal(r.compressIPv6(t.e), t.c)
      })
    }
  })

  describe('expandIPv6', function () {
    const r = new RR(null)
    for (const t of tests) {
      it(`expands IPv6 address (${t.c})`, function () {
        assert.equal(r.expandIPv6(t.c), t.e)
      })
    }
  })

  describe('getComment', function () {
    it('returns empty string when no comment is set', function () {
      const rr = new RR(null)
      assert.equal(rr.getComment('owner'), '')
    })

    it('returns the comment value for a given property', function () {
      const rr = new RR(null)
      rr.set('comment', { owner: 'test comment value' })
      assert.equal(rr.getComment('owner'), 'test comment value')
      assert.equal(rr.getComment('nonexistent'), '')
    })
  })

  describe('getPrefix with sameOwner', function () {
    it('returns empty owner when sameOwner is hidden', function () {
      const rr = new A({ owner: 'example.com.', ttl: 3600, class: 'IN', type: 'A', address: '1.2.3.4' })
      const prefix = rr.getPrefix({ hide: { sameOwner: true }, previousOwner: 'example.com.' })
      assert.equal(prefix, '\t3600\tIN\tA')
    })
  })

  describe('getTinyFQDN edge cases', function () {
    it('returns empty string for empty value', function () {
      const rr = new RR(null)
      rr.set('target', '')
      assert.equal(rr.getTinyFQDN('target'), '')
    })

    it("returns '.' for null MX target", function () {
      const rr = new RR(null)
      rr.set('target', '.')
      assert.equal(rr.getTinyFQDN('target'), '.')
    })
  })

  describe('isValidHostname error path', function () {
    it('throws on invalid hostname character', function () {
      const rr = new RR(null)
      assert.throws(
        () => rr.isValidHostname('TEST', 'hostname', 'host@example.com'),
        /invalid hostname character/,
      )
    })
  })

  describe('toMaraDNS', function () {
    it('exports supported types in MaraDNS format', function () {
      const a = new A({ owner: 'example.com.', ttl: 3600, class: 'IN', type: 'A', address: '1.2.3.4' })
      assert.equal(a.toMaraDNS(), 'example.com.\t+3600\tA\t1.2.3.4 ~\n')
    })

    it('exports unsupported types via toMaraGeneric', function () {
      const key = new KEY({
        owner: 'example.com.',
        ttl: 3600,
        class: 'IN',
        type: 'KEY',
        flags: 256,
        protocol: 3,
        algorithm: 5,
        publickey: 'AQIDBA==',
      })
      const out = key.toMaraDNS()
      // wire rdata (flags, protocol, algorithm, key) as unquoted \xNN escapes
      assert.equal(out, 'example.com.\t+3600\tRAW 25\t\\x01\\x00\\x03\\x05\\x01\\x02\\x03\\x04 ~\n')
    })

    it('throws on non-IN class instead of silently dropping it', function () {
      const a = new A({ owner: 'example.com.', ttl: 3600, class: 'CH', type: 'A', address: '1.2.3.4' })
      assert.throws(() => a.toMaraDNS(), /only class IN/)
    })

    // TXT and SOA override toMaraDNS, so the guard must hold there too
    it('throws on non-IN class in the TXT override', function () {
      const t = new TXT({ owner: 'e.example.', ttl: 3600, class: 'CH', type: 'TXT', data: 'x' })
      assert.throws(() => t.toMaraDNS(), /only class IN/)
    })

    it('throws on non-IN class in the SOA override', function () {
      const soa = new SOA({ ...new SOA(null).getCanonical(), class: 'CH' })
      assert.throws(() => soa.toMaraDNS(), /only class IN/)
    })
  })

  describe('toTinydns class guard', function () {
    it('throws on non-IN class instead of silently dropping it', function () {
      const a = new A({ owner: 'example.com.', ttl: 3600, class: 'CH', type: 'A', address: '1.2.3.4' })
      assert.throws(() => a.toTinydns(), /only class IN/)
    })

    // MX and TXT override toTinydns with shorthand emitters; the guard sits in
    // getTinydnsPostamble, which every tinydns line passes through
    it('throws on non-IN class in the MX override', function () {
      const mx = new MX({
        owner: 'e.example.',
        ttl: 3600,
        class: 'CH',
        type: 'MX',
        preference: 10,
        exchange: 'mail.example.',
      })
      assert.throws(() => mx.toTinydns(), /only class IN/)
    })

    it('throws on non-IN class in the TXT override', function () {
      const t = new TXT({ owner: 'e.example.', ttl: 3600, class: 'CH', type: 'TXT', data: 'x' })
      assert.throws(() => t.toTinydns(), /only class IN/)
    })
  })

  describe('fromWire strictness', function () {
    const a = new A({ owner: 'example.com.', ttl: 3600, class: 'IN', type: 'A', address: '10.0.0.1' })
    const wire = a.toWire()

    it('round-trips a valid record', function () {
      assert.equal(A.fromWire(wire).get('address'), '10.0.0.1')
    })

    it('throws on trailing garbage after rdata', function () {
      const longer = new Uint8Array([...wire, 0xff])
      assert.throws(() => A.fromWire(longer), /RDLENGTH/)
    })

    it('throws on truncated rdata', function () {
      assert.throws(() => A.fromWire(wire.slice(0, wire.length - 2)), /RDLENGTH/)
    })

    it('throws on a truncated header', function () {
      assert.throws(() => A.fromWire(wire.slice(0, 20)), /truncated/)
    })

    it('throws when the wire type id does not match the class', function () {
      assert.throws(() => TXT.fromWire(wire), /wire type id 1 does not match 16/)
    })

    it('preserves an unknown class through wire round-trip (RFC 3597)', function () {
      const c32 = new A({
        owner: 'example.com.',
        ttl: 3600,
        class: 'CLASS32',
        type: 'A',
        address: '10.0.0.1',
      })
      assert.equal(A.fromWire(c32.toWire()).get('class'), 'CLASS32')
    })
  })

  describe('fromBind', function () {
    it('preserves a non-IN class', function () {
      assert.equal(TXT.fromBind('version.bind. 0 CH TXT "9.18.1"').get('class'), 'CH')
    })

    it('rejoins opaque rdata split across whitespace', function () {
      // RFC 4034 §5.4 writes the digest in two whitespace separated halves
      const ds = DS.fromBind(
        'dskey.example.com. 86400 IN DS 60485 5 1 2BB183AF5F22588179A53B0A 98631FAD1A292118',
      )
      assert.equal(ds.get('digest'), '2BB183AF5F22588179A53B0A98631FAD1A292118')
    })
  })
})
