import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import RRBase, * as RR from '../index.js'
import { tokenize } from '../lib/bind.js'
import { wirePackDomain, wireUnpackDomain } from '../lib/wire.js'

const adversarial = [
  'quote"value',
  'back\\slash',
  'a";still data',
  'semi;colon',
  'paren(s)',
  'two  spaces',
  '',
]
const controls = [
  'line\nbreak',
  'tab\tvalue',
  'carriage\rreturn',
  'a\u0000b',
  'a\u001ab',
  'a\u007fb',
  'é and 日本',
]

function roundTrip(type, opts) {
  const bind = new type(opts).toBind()
  return { bind, rr: type.fromBind(bind) }
}

describe('tokenize', function () {
  it('ends a token at a closing quote', function () {
    assert.deepEqual(tokenize('"a"b'), [
      { text: 'a', quoted: true },
      { text: 'b', quoted: false, adjoins: true },
    ])
    assert.deepEqual(tokenize('"a""b"'), [
      { text: 'a', quoted: true },
      { text: 'b', quoted: true, adjoins: true },
    ])
  })

  it('marks tokens with no whitespace before them', function () {
    assert.deepEqual(tokenize('k="v" (x)y'), [
      { text: 'k=', quoted: false },
      { text: 'v', quoted: true, adjoins: true },
      { text: 'x', quoted: false },
      { text: 'y', quoted: false },
    ])
  })

  it('keeps empty quoted strings', function () {
    assert.deepEqual(tokenize('""'), [{ text: '', quoted: true }])
  })

  it('keeps escapes in token text', function () {
    assert.deepEqual(tokenize('a\\.b "c\\"d" \\#'), [
      { text: 'a\\.b', quoted: false },
      { text: 'c\\"d', quoted: true },
      { text: '\\#', quoted: false },
    ])
  })

  it('treats an escaped space as token data', function () {
    assert.deepEqual(tokenize('a\\ b'), [{ text: 'a\\ b', quoted: false }])
  })

  it('ends comments at the newline, not the input', function () {
    assert.deepEqual(
      tokenize('( 1 ; first\n 2 ) ; last').map((t) => t.text),
      ['1', '2'],
    )
  })

  it('allows trailing blank lines after a record', function () {
    assert.deepEqual(tokenize('a b\n\n  \n'), [
      { text: 'a', quoted: false },
      { text: 'b', quoted: false },
    ])
  })

  it('ignores ; and parens inside quotes', function () {
    assert.deepEqual(tokenize('"a;(b)" ; c'), [{ text: 'a;(b)', quoted: true }])
  })

  for (const bad of [
    '"unfinished',
    '"trailing\\',
    'trailing\\',
    '( unclosed',
    'unopened )',
    '"a\nb"',
    'x. TXT "a"\ny. TXT "b"',
  ]) {
    it(`rejects ${JSON.stringify(bad)}`, function () {
      assert.throws(() => tokenize(bad), /^Error: BIND:/)
    })
  }
})

describe('character-string escapes', function () {
  it('decodes \\X and \\DDD', function () {
    const rr = RR.TXT.fromBind('x.example. 300 IN TXT "a\\";b\\032c\\195\\169" ; comment')
    assert.equal(rr.get('data'), 'a";b cé')
  })

  for (const [text, data] of [
    ['bare\\"', 'bare"'],
    ['\\"bare', '"bare'],
    ['\\"bare\\"', '"bare"'],
  ]) {
    it(`decodes unquoted escaped quotes: ${text}`, function () {
      assert.equal(RR.TXT.fromBind(`x.example. 300 IN TXT ${text}`).get('data'), data)
    })
  }

  for (const bad of ['"\\999"', '"\\25"', '"\\255"']) {
    it(`rejects ${bad}`, function () {
      assert.throws(() => RR.TXT.fromBind(`x.example. 300 IN TXT ${bad}`), /^Error: BIND:/)
    })
  }

  it('writes control characters as \\DDD', function () {
    const bind = new RR.TXT({ owner: 'x.example.', ttl: 300, data: 'a\n\u0000\u007f' }).toBind()
    assert.equal(bind, 'x.example.\t300\tIN\tTXT\t"a\\010\\000\\127"\n')
  })

  it('accepts TXT rdata split across parens', function () {
    assert.deepEqual(RR.TXT.fromBind('x.example. 300 IN TXT ( "a"\n "b" )').get('data'), ['a', 'b'])
  })
})

describe('quoted fields round trip', function () {
  for (const data of [...adversarial, ...controls, ['a"b', 'c\\d']]) {
    it(`TXT ${JSON.stringify(data)}`, function () {
      const { bind, rr } = roundTrip(RR.TXT, { owner: 'x.example.', ttl: 300, data })
      assert.ok([...bind.slice(0, -1)].every((c) => c === '\t' || (c >= ' ' && c !== '\x7f')))
      assert.deepEqual(rr.get('data'), data)
    })
  }

  for (const value of [...adversarial, ...controls]) {
    it(`HINFO, CAA, URI and NAPTR ${JSON.stringify(value)}`, function () {
      const hinfo = roundTrip(RR.HINFO, { owner: 'x.example.', ttl: 300, cpu: value, os: value }).rr
      assert.equal(hinfo.get('cpu'), value)
      assert.equal(hinfo.get('os'), value)

      const caa = { owner: 'x.example.', ttl: 300, flags: 0, tag: 'issue', value }
      assert.equal(roundTrip(RR.CAA, caa).rr.get('value'), value)

      if (value !== '') {
        const uri = { owner: 'x.example.', ttl: 300, priority: 1, weight: 1, target: value }
        assert.equal(roundTrip(RR.URI, uri).rr.get('target'), value)
      }

      const naptr = {
        owner: 'x.example.',
        ttl: 300,
        order: 1,
        preference: 1,
        flags: 'U',
        service: 'E2U+sip',
        regexp: value,
        replacement: '.',
      }
      assert.equal(roundTrip(RR.NAPTR, naptr).rr.get('regexp'), value)
    })
  }

  for (const value of ['"x', 'x"', '"x"', "'x'"]) {
    it(`HINFO and CAA keep edge quotes: ${value}`, function () {
      const { rr } = roundTrip(RR.HINFO, { owner: 'x.example.', ttl: 300, cpu: value, os: value })
      assert.equal(rr.get('cpu'), value)
      assert.equal(rr.get('os'), value)
      const caa = { owner: 'x.example.', ttl: 300, flags: 0, tag: 'issue', value }
      assert.equal(roundTrip(RR.CAA, caa).rr.get('value'), value)
    })
  }

  it('NAPTR backreferences survive', function () {
    const regexp = '!^.*$!sip:\\1@example.com!'
    const { bind, rr } = roundTrip(RR.NAPTR, {
      owner: 'x.example.',
      ttl: 300,
      order: 1,
      preference: 1,
      flags: 'U',
      service: 'E2U+sip',
      regexp,
      replacement: '.',
    })
    assert.match(bind, /"!\^\.\*\$!sip:\\\\1@example\.com!"/)
    assert.equal(rr.get('regexp'), regexp)
  })
})

describe('names keep their presentation escapes', function () {
  it('a \\. inside a label is not a label break', function () {
    assert.equal(RR.A.fromBind('a\\.b.example. 300 IN A 192.0.2.1').get('owner'), 'a\\.b.example.')
  })

  it('a \\. is one label on the wire', function () {
    const rr = RR.A.fromBind('a\\.b.example. 300 IN A 192.0.2.1')
    assert.deepEqual(
      [...wirePackDomain(rr.get('owner'))],
      [3, 0x61, 0x2e, 0x62, 7, ...Buffer.from('example'), 0],
    )
    assert.equal(RR.A.fromWire(rr.toWire()).get('owner'), 'a\\.b.example.')
  })

  it('\\DDD is one octet on the wire', function () {
    assert.deepEqual([...wirePackDomain('a\\032b.')], [3, 0x61, 0x20, 0x62, 0])
    assert.deepEqual([...wirePackDomain('\\065.')], [1, 0x41, 0])
  })

  for (const name of [
    'a\\.b.example.',
    'back\\\\slash.example.',
    'sp\\032ace.example.',
    'x\\195\\169.example.',
  ]) {
    it(`unpacks to the same presentation: ${name}`, function () {
      assert.equal(wireUnpackDomain(wirePackDomain(name)).fqdn, name)
    })
  }

  it('counts label length in octets, not escape characters', function () {
    const label = '\\065'.repeat(63)
    assert.equal(
      RR.A.fromBind(`${label}.example. 300 IN A 192.0.2.1`).get('owner'),
      `${label}.example.`.toLowerCase(),
    )
    assert.throws(() => RR.A.fromBind(`${label}\\065.example. 300 IN A 192.0.2.1`), /exceeds 63 bytes/)
  })

  it('limits names to 255 octets on the wire', function () {
    const label = 'a'.repeat(63)
    const fits = `${label}.${label}.${label}.${'a'.repeat(61)}.`
    assert.equal(RR.A.fromBind(`${fits} 300 IN A 192.0.2.1`).get('owner'), fits)
    assert.throws(() => RR.A.fromBind(`a.${fits} 300 IN A 192.0.2.1`), /1-255 octets, got 257/)
  })

  // Wire decoding writes delimiters as \DDD, so the second column is the form fromWire returns.
  for (const [owner, fromWire] of [
    ['two\\032words.example.', 'two\\032words.example.'],
    ['semi\\;colon.example.', 'semi\\059colon.example.'],
    ['quote\\"name.example.', 'quote\\034name.example.'],
    ['slash\\\\name.example.', 'slash\\\\name.example.'],
    ['paren\\(name\\).example.', 'paren\\040name\\041.example.'],
    ['wide\\226\\128\\131space.example.', 'wide\\226\\128\\131space.example.'],
  ]) {
    it(`round trips an escaped owner: ${owner}`, function () {
      const rr = new RR.TXT({ owner, ttl: 300, data: 'fixture' })
      assert.equal(RR.TXT.fromBind(rr.toBind()).get('owner'), owner)
      assert.equal(RR.TXT.fromWire(rr.toWire()).get('owner'), fromWire)
    })

    it(`round trips an escaped rdata name: ${owner}`, function () {
      for (const [type, rdata, field] of [
        ['CNAME', owner, 'cname'],
        ['DNAME', owner, 'target'],
        ['NS', owner, 'dname'],
        ['SVCB', `1 ${owner}`, 'target name'],
        ['RP', `${owner} ${owner}`, 'mbox'],
        ['RP', `${owner} ${owner}`, 'txt'],
        ['NAPTR', `1 1 "u" "E2U+sip" "" ${owner}`, 'replacement'],
      ]) {
        const rr = RR[type].fromBind(`x.example. 300 IN ${type} ${rdata}`)
        assert.equal(rr.get(field), owner, type)
        assert.equal(RR[type].fromWire(rr.toWire()).get(field), fromWire, type)
      }
    })
  }

  for (const [type, field] of [
    ['CNAME', 'cname'],
    ['RP', 'mbox'],
    ['RP', 'txt'],
    ['NAPTR', 'replacement'],
    ['SIG', 'signers name'],
  ]) {
    it(`rejects an unescaped delimiter in ${type} ${field}`, function () {
      const canonical = new RR[type](null).getCanonical()
      assert.throws(
        () => new RR[type]({ ...canonical, [field]: 'a(b.example.' }),
        new RegExp(`${type}: ${field} has an unescaped delimiter`),
      )
    })
  }

  for (const owner of [
    'two words.example.',
    'semi;colon.example.',
    'quote"name.example.',
    'paren(name).example.',
    'wide\u2003space.example.',
  ]) {
    it(`rejects an unescaped delimiter in an owner: ${JSON.stringify(owner)}`, function () {
      assert.throws(() => new RR.TXT({ owner, ttl: 300, data: 'fixture' }), /unescaped delimiter/)
    })
  }

  it('folds only ASCII letters (RFC 4343)', function () {
    assert.equal(RR.A.fromBind('ÉCOLE.Example. 300 IN A 192.0.2.1').get('owner'), 'École.example.')
  })

  it('lowercases names but keeps escaped octets as written (RFC 4343)', function () {
    const a = RR.A.fromBind('ABC\\065\\A.Example. 300 IN A 192.0.2.1')
    assert.equal(a.get('owner'), 'abc\\065\\A.example.')
    const ns = RR.NS.fromBind('x.example. 300 IN NS Name\\B.Example.')
    assert.equal(ns.get('dname'), 'name\\B.example.')
  })

  it('accepts an escaped * inside a label', function () {
    for (const owner of ['a\\*b.example.', 'a\\042b.example.']) {
      assert.equal(RR.A.fromBind(`${owner} 300 IN A 192.0.2.1`).get('owner'), owner)
    }
  })

  it('rejects * except as the whole leftmost label (RFC 4592)', function () {
    for (const owner of ['a*b.example.', '*.a*b.example.', 'a.*.example.', '**.example.'])
      assert.throws(() => new RR.A({ owner, ttl: 300, type: 'A', address: '192.0.2.1' }), /valid wildcard/)
    assert.equal(
      new RR.A({ owner: 'a.\\*.example.', ttl: 300, type: 'A', address: '192.0.2.1' }).get('owner'),
      'a.\\*.example.',
    )
  })

  it('round trips * through wire as a wildcard label or an escaped byte', function () {
    for (const [owner, expected] of [
      ['*.example.', '*.example.'],
      ['a\\*b.example.', 'a\\042b.example.'],
    ]) {
      const rr = RR.A.fromBind(`${owner} 300 IN A 192.0.2.1`)
      assert.equal(RR.A.fromWire(rr.toWire()).get('owner'), expected)
    }
  })

  it('rejects an empty label', function () {
    assert.throws(() => RR.A.fromBind('a..example. 300 IN A 192.0.2.1'), /empty label/)
  })

  for (const bad of ['a\\', 'a\\25.', 'a\\256.', 'a..b.']) {
    it(`rejects ${JSON.stringify(bad)}`, function () {
      assert.throws(() => wirePackDomain(bad), /DNS name/)
    })
  }
})

describe('generic rdata', function () {
  it('a quoted \\# is a character-string', function () {
    assert.equal(RR.TXT.fromBind('x.example. 300 IN TXT "\\# 0"').get('data'), '# 0')
  })

  it('rejects missing rdata', function () {
    assert.throws(() => RR.MX.fromBind('x.example. 300 IN MX 10'), /MX: missing rdata: exchange/)
  })

  it('rejects surplus rdata', function () {
    assert.throws(
      () => RR.A.fromBind('x.example. 300 IN A 192.0.2.1 192.0.2.2'),
      /A: unexpected rdata: 192.0.2.2/,
    )
  })

  it('rejects a different type', function () {
    assert.throws(() => RR.A.fromBind('x.example. 300 IN MX 10 mx.example.'), /expected A, got MX/)
    assert.throws(() => RR.A.fromBind('x.example. 300 IN'), /expected A, got no type/)
  })

  it('rejects a different type before a custom importer runs', function () {
    const rrsig = new RR.RRSIG(new RR.RRSIG(null).getCanonical()).toBind().replace('\tRRSIG\t', '\tSIG\t')
    assert.throws(() => RR.RRSIG.fromBind(rrsig), /expected RRSIG, got SIG/)
  })

  it('rejects surplus tokens for a single character-string', function () {
    assert.throws(
      () => RR.CAA.fromBind('x.example. 300 IN CAA 0 issue one two'),
      /CAA: unexpected rdata: two/,
    )
    assert.throws(
      () => RR.URI.fromBind('x.example. 300 IN URI 1 1 "https://a" "https://b"'),
      /URI: unexpected rdata: https:\/\/b/,
    )
  })

  it('keeps all-digit tokens as text in non-numeric fields', function () {
    const nsec3 = RR.NSEC3.fromBind('x.example. 300 IN NSEC3 2 0 0 1234 12345678 A')
    assert.equal(nsec3.get('salt'), '1234')
    assert.equal(nsec3.get('next hashed owner name'), '12345678')
    assert.equal(RR.NSEC3PARAM.fromBind('x.example. 300 IN NSEC3PARAM 1 0 0 1234').get('salt'), '1234')
    assert.equal(RR.HIP.fromBind('x.example. 300 IN HIP 2 20010010 1234').get('hit'), '20010010')
  })
})

describe('list rdata', function () {
  it('joins the rest of the rdata across parens and comments', function () {
    const rr = RR.NSEC.fromBind('a.example. 300 IN NSEC b.example. ( A ; addr\n RRSIG )')
    assert.equal(rr.get('type bit maps'), 'A RRSIG')
  })

  it('may be empty', function () {
    const rr = RR.SVCB.fromBind('a.example. 300 IN SVCB 0 b.example.')
    assert.equal(rr.get('params'), '')
  })

  it('keeps quoted values attached to their keys', function () {
    const rr = RR.SVCB.fromBind('a.example. 300 IN SVCB 1 . ( alpn="h2,h3" ; comment\n port="8004" )')
    assert.equal(rr.get('params'), 'alpn="h2,h3" port=8004')
  })

  it('still requires the fields before it', function () {
    assert.throws(() => RR.WKS.fromBind('a.example. 300 IN WKS 192.0.2.1'), /WKS: missing rdata: protocol/)
  })
})

describe('canonical records round trip through BIND', function () {
  for (const type of Object.values(RR).filter(
    (c) => c?.prototype instanceof RRBase && c.typeId !== undefined,
  )) {
    it(type.typeName, function () {
      const canonical = new type(null).getCanonical()
      assert.deepEqual(type.fromBind(new type(canonical).toBind()).toJSON(), new type(canonical).toJSON())
    })
  }
})
