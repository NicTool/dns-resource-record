import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import RRBase, * as RR from '../index.js'
import { tokenize } from '../lib/bind.js'

const adversarial = [
  'quote"value',
  'back\\slash',
  'a";still data',
  'semi;colon',
  'paren(s)',
  'two  spaces',
  '',
]
const controls = ['line\nbreak', 'tab\tvalue', 'carriage\rreturn', 'a\u0000b', 'a\u007fb', 'é and 日本']

function roundTrip(type, opts) {
  const bind = new type(opts).toBind()
  return { bind, rr: type.fromBind(bind) }
}

describe('tokenize', function () {
  it('ends a token at a closing quote', function () {
    assert.deepEqual(tokenize('"a"b'), [
      { text: 'a', quoted: true },
      { text: 'b', quoted: false },
    ])
    assert.deepEqual(tokenize('"a""b"'), [
      { text: 'a', quoted: true },
      { text: 'b', quoted: true },
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

  it('decodes unquoted escaped quotes', function () {
    assert.equal(RR.TXT.fromBind('x.example. 300 IN TXT \\"bare\\"').get('data'), '"bare"')
  })

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
    assert.throws(() => RR.A.fromBind('x.example. 300 IN MX 10 mx.example.'), /A: cannot parse a MX record/)
  })

  it('rejects a different type before a custom importer runs', function () {
    const rrsig = new RR.RRSIG(new RR.RRSIG(null).getCanonical()).toBind().replace('\tRRSIG\t', '\tSIG\t')
    assert.throws(() => RR.RRSIG.fromBind(rrsig), /RRSIG: cannot parse a SIG record/)
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
})

describe('canonical records round trip through BIND', function () {
  for (const type of Object.values(RR).filter(
    (c) => c?.prototype instanceof RRBase && c.typeId !== undefined,
  )) {
    // NSEC3 stores type bit maps as a space- or tab-joined string depending on the importer
    const skip = type.typeName === 'NSEC3'
    it(type.typeName, { skip }, function () {
      const canonical = new type(null).getCanonical()
      assert.deepEqual(type.fromBind(new type(canonical).toBind()).toJSON(), new type(canonical).toJSON())
    })
  }
})
