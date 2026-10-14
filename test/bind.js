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
  it('splits tokens, marking quotes and tokens with no whitespace before them', function () {
    const t = (text, quoted, adjoins) => ({ text, quoted, ...(adjoins && { adjoins }) })
    for (const [line, tokens] of [
      ['"a"b', [t('a', true), t('b', false, true)]],
      ['"a""b"', [t('a', true), t('b', true, true)]],
      ['k="v" (x)y', [t('k=', false), t('v', true, true), t('x', false), t('y', false)]],
      ['""', [t('', true)]],
      ['a\\.b "c\\"d" \\#', [t('a\\.b', false), t('c\\"d', true), t('\\#', false)]],
      ['a\\ b', [t('a\\ b', false)]],
      ['a b\n\n  \n', [t('a', false), t('b', false)]],
      ['"a;(b)" ; c', [t('a;(b)', true)]],
    ]) {
      assert.deepEqual(tokenize(line), tokens, JSON.stringify(line))
    }
    assert.deepEqual(
      tokenize('( 1 ; first\n 2 ) ; last').map((t) => t.text),
      ['1', '2'],
    )
  })

  it('rejects malformed input', function () {
    assert.throws(() => tokenize('x. TXT "a" ; comment\ny. TXT "b"'), /text after end of record/)
    for (const bad of [
      '"unfinished',
      '"trailing\\',
      'trailing\\',
      '( unclosed',
      'unopened )',
      '"a\nb"',
      'x. TXT "a"\ny. TXT "b"',
    ])
      assert.throws(() => tokenize(bad), /^Error: BIND:/, JSON.stringify(bad))
  })
})

describe('character-string escapes', function () {
  const txt = (rdata) => RR.TXT.fromBind(`x.example. 300 IN TXT ${rdata}`).get('data')

  it('decodes \\X and \\DDD', function () {
    for (const [rdata, data] of [
      ['"a\\";b\\032c\\195\\169" ; comment', 'a";b cé'],
      ['bare\\"', 'bare"'],
      ['\\"bare', '"bare'],
      ['\\"bare\\"', '"bare"'],
      ['( "a"\n "b" )', ['a', 'b']],
    ]) {
      assert.deepEqual(txt(rdata), data, rdata)
    }
    for (const bad of ['"\\999"', '"\\25"', '"\\255"']) assert.throws(() => txt(bad), /^Error: BIND:/, bad)
  })

  it('writes control characters as \\DDD', function () {
    const bind = new RR.TXT({ owner: 'x.example.', ttl: 300, data: 'a\n\u0000\u007f' }).toBind()
    assert.equal(bind, 'x.example.\t300\tIN\tTXT\t"a\\010\\000\\127"\n')
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
  const owner = (name) => RR.A.fromBind(`${name} 300 IN A 192.0.2.1`).get('owner')

  it('packs \\. and \\DDD as one octet in a label', function () {
    for (const [name, wire] of [
      ['a\\.b.example.', '03612e62076578616d706c6500'],
      ['a\\032b.', '0361206200'],
      ['\\065.', '014100'],
    ]) {
      assert.equal(Buffer.from(wirePackDomain(name)).toString('hex'), wire, name)
    }
    assert.equal(owner('a\\.b.example.'), 'a\\.b.example.')
    assert.equal(
      RR.A.fromWire(RR.A.fromBind('a\\.b.example. 300 IN A 192.0.2.1').toWire()).get('owner'),
      'a\\.b.example.',
    )
    for (const name of [
      'a\\.b.example.',
      'back\\\\slash.example.',
      'sp\\032ace.example.',
      'x\\195\\169.example.',
    ])
      assert.equal(wireUnpackDomain(wirePackDomain(name)).fqdn, name)
  })

  it('limits labels to 63 octets and names to 255, counting octets', function () {
    const escaped = '\\065'.repeat(63)
    assert.equal(owner(`${escaped}.example.`), `${escaped}.example.`.toLowerCase())
    assert.throws(() => owner(`${escaped}\\065.example.`), /exceeds 63 bytes/)

    const label = 'a'.repeat(63)
    const fits = `${label}.${label}.${label}.${'a'.repeat(61)}.`
    assert.equal(owner(fits), fits)
    assert.throws(() => owner(`a.${fits}`), /1-255 octets, got 257/)
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

  // RFC 4343
  it('lowercases only ASCII letters, keeping escaped octets as written', function () {
    assert.equal(owner('ÉCOLE.Example.'), 'École.example.')
    assert.equal(owner('ABC\\065\\A.Example.'), 'abc\\065\\A.example.')
    assert.equal(RR.NS.fromBind('x.example. 300 IN NS Name\\B.Example.').get('dname'), 'name\\B.example.')
  })

  // RFC 4592
  it('accepts * only as the whole leftmost label, or escaped', function () {
    for (const name of ['a\\*b.example.', 'a\\042b.example.']) assert.equal(owner(name), name)
    for (const name of ['a*b.example.', '*.a*b.example.', 'a.*.example.', '**.example.'])
      assert.throws(() => new RR.A({ owner: name, ttl: 300, address: '192.0.2.1' }), /valid wildcard/)
    assert.equal(
      new RR.A({ owner: 'a.\\*.example.', ttl: 300, address: '192.0.2.1' }).get('owner'),
      'a.\\*.example.',
    )
    for (const [name, fromWire] of [
      ['*.example.', '*.example.'],
      ['a\\*b.example.', 'a\\042b.example.'],
    ]) {
      assert.equal(RR.A.fromWire(RR.A.fromBind(`${name} 300 IN A 192.0.2.1`).toWire()).get('owner'), fromWire)
    }
  })

  it('rejects empty labels and bad escapes', function () {
    assert.throws(() => owner('a..example.'), /empty label/)
    for (const bad of ['a\\', 'a\\25.', 'a\\256.', 'a..b.'])
      assert.throws(() => wirePackDomain(bad), /DNS name/, bad)
  })
})

describe('generic rdata', function () {
  it('a quoted \\# is a character-string', function () {
    assert.equal(RR.TXT.fromBind('x.example. 300 IN TXT "\\# 0"').get('data'), '# 0')
  })

  it('rejects missing, surplus or mistyped rdata', function () {
    const rrsig = new RR.RRSIG(new RR.RRSIG(null).getCanonical()).toBind().replace('\tRRSIG\t', '\tSIG\t')
    for (const [type, line, msg] of [
      ['MX', 'x.example. 300 IN MX 10', /MX: missing rdata: exchange/],
      ['A', 'x.example. 300 IN A 192.0.2.1 192.0.2.2', /A: unexpected rdata: 192.0.2.2/],
      ['A', 'x.example. 300 IN MX 10 mx.example.', /expected A, got MX/],
      ['A', 'x.example. 300 IN', /expected A, got no type/],
      // before a custom importer runs
      ['RRSIG', rrsig, /expected RRSIG, got SIG/],
      // a single character-string takes one token
      ['CAA', 'x.example. 300 IN CAA 0 issue one two', /CAA: unexpected rdata: two/],
      ['URI', 'x.example. 300 IN URI 1 1 "https://a" "https://b"', /URI: unexpected rdata: https:\/\/b/],
    ]) {
      assert.throws(() => RR[type].fromBind(line), msg, line)
    }
  })

  it('keeps all-digit tokens as text in non-numeric fields', function () {
    for (const [line, field, value] of [
      ['x.example. 300 IN NSEC3 2 0 0 1234 12345678 A', 'salt', '1234'],
      ['x.example. 300 IN NSEC3 2 0 0 1234 12345678 A', 'next hashed owner name', '12345678'],
      ['x.example. 300 IN NSEC3PARAM 1 0 0 1234', 'salt', '1234'],
      ['x.example. 300 IN HIP 2 20010010 1234', 'hit', '20010010'],
    ]) {
      assert.equal(RR[line.split(' ')[3]].fromBind(line).get(field), value)
    }
  })
})

describe('list rdata', function () {
  it('joins the rest of the rdata across parens, comments and quotes', function () {
    for (const [type, line, field, value] of [
      ['NSEC', 'a.example. 300 IN NSEC b.example. ( A ; addr\n RRSIG )', 'type bit maps', 'A RRSIG'],
      ['SVCB', 'a.example. 300 IN SVCB 0 b.example.', 'params', ''],
      [
        'SVCB',
        'a.example. 300 IN SVCB 1 . ( alpn="h2,h3" ; comment\n port="8004" )',
        'params',
        'alpn="h2,h3" port=8004',
      ],
    ]) {
      assert.equal(RR[type].fromBind(line).get(field), value)
    }
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
