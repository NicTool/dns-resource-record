import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import TXT from '../../rr/txt.js'

const DKIM =
  'v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN/nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64/cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob' +
  '4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn/LAf+3kzW58AjsERpsNCSTD2RquxbnyoR/1wdGKb8cUlD/EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB'

// a string over 255 bytes is two character-strings on the wire
const dkim = {
  owner: 'oct2021._domainkey.example.com.',
  ttl: 86400,
  data: DKIM,
  testB: `oct2021._domainkey.example.com.\t86400\tIN\tTXT\t"${DKIM.slice(0, 255)}" "${DKIM.slice(255)}"\n`,
  testT: `:oct2021._domainkey.example.com:16:\\377${DKIM.slice(0, 255)}\\223${DKIM.slice(255)}:86400::\n`,
  testW:
    '076f6374323032310a5f646f6d61696e6b6579076578616d706c6503636f6d0000100001000151800194ff763d444b494d313b703d4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b43415145416f79557a474f54534f6d616b5938426378586769306d4e2f6e4665674c425073376161475155746a48666138795572743954326a3647535867646a4c754733523433576a655051763352487a632b6277774f6b64773058444f58697a746e356d68726c61666c62567235504d5354727636342f637046514b4c746751783856677170374468336a773133724c6f6d5254714a46674d724d4864684969625a45613639677475416644716f65586f36514453476b354a7542416552484548323746726948756c67356f62933446346c6d6837664d46567344476b514546366a614956597176526a44797951656433523361544a583366706233517274527176666e2f4c41662b336b7a573538416a73455270734e435354443252717578626e796f522f317764474b623863556c442f45587671747670566e4f7a486553654d45716578336b514938484f4773456568575a6c4b642b477177494441514142',
}

const valid = [
  dkim,
  { ...dkim, data: [DKIM.slice(0, 255), DKIM.slice(255)] },
  {
    owner: 'example.com.',
    ttl: 86400,
    data: 'v=spf1 mx a include:mx.example.com -all',
    testB: 'example.com.\t86400\tIN\tTXT\t"v=spf1 mx a include:mx.example.com -all"\n',
    testT: "'example.com:v=spf1 mx a include\\072mx.example.com -all:86400::\n",
    testW:
      '076578616d706c6503636f6d000010000100015180002827763d73706631206d78206120696e636c7564653a6d782e6578616d706c652e636f6d202d616c6c',
  },
  {
    owner: 'nictool.tnpi.net.',
    data: ['v=spf1 mx include:tnpi.net -all'],
    testB: 'nictool.tnpi.net.\t3600\tIN\tTXT\t"v=spf1 mx include:tnpi.net -all"\n',
    testT: ':nictool.tnpi.net:16:\\037v=spf1 mx include\\072tnpi.net -all:3600::\n',
    testW:
      '076e6963746f6f6c04746e7069036e6574000010000100000e1000201f763d73706631206d7820696e636c7564653a746e70692e6e6574202d616c6c',
  },
]

const octal = (s) => [...s].map((c) => `\\${c.charCodeAt(0).toString(8).padStart(3, '0')}`).join('')
const txt = (data, owner = 'example.com.') => new TXT({ owner, ttl: 3600, data })

describe('TXT record', function () {
  base.suite(TXT, { typeId: 16, fields: ['data'], valid })

  it('chunks BIND and wire character-strings on UTF-8 byte boundaries', function () {
    const quoted = txt('é'.repeat(200))
      .toBind()
      .match(/"([^"]*)"/g)
    assert.ok(quoted.length > 1)
    for (const q of quoted) assert.ok(new TextEncoder().encode(q.slice(1, -1)).length <= 255, q)
    assert.equal(quoted.map((q) => q.slice(1, -1)).join(''), 'é'.repeat(200))

    const r = txt(`${'a'.repeat(254)}é`)
    assert.deepEqual(TXT.fromWire(r.toWire()).get('data'), ['a'.repeat(254), 'é'])
    assert.deepEqual(TXT.fromBind(r.toBind()).get('data'), ['a'.repeat(254), 'é'])
  })

  it('imports a generic tinydns line written entirely in octal', function () {
    const r = TXT.fromTinydns(
      `:${dkim.owner.slice(0, -1)}:16:\\377${octal(DKIM.slice(0, 255))}\\223${octal(DKIM.slice(255))}:86400::\n`,
    )
    assert.deepEqual(r.get('data'), valid[1].data)
    assert.equal(r.get('owner'), dkim.owner)
  })

  // RFC 1035 §3.3.14: multi-string TXT records are wire-distinct from one
  // concatenated string, so boundaries must round-trip.
  it('keeps character-string boundaries', function () {
    const segments = ['hello', 'world']
    assert.deepEqual(
      [...txt(segments).getWireRdata()],
      [5, ...Buffer.from('hello'), 5, ...Buffer.from('world')],
    )
    assert.deepEqual(TXT.fromWire(txt(segments).toWire()).get('data'), segments)
    assert.equal(TXT.fromWire(txt('just one').toWire()).get('data'), 'just one')
    assert.deepEqual(TXT.fromBind('example.com.\t3600\tIN\tTXT\t"hello" "world"\n').get('data'), segments)
  })

  it('rejects data that is not a string or an array of <=255 byte strings', function () {
    assert.throws(() => txt(['ok', 'x'.repeat(256)]), /each string in a data array must be <=255 bytes/)
    assert.throws(() => txt([]), /non-empty array of strings/)
    assert.throws(() => txt(undefined), /must be a string/)
  })

  it('rejects a truncated character-string', function () {
    assert.throws(() => TXT.fromTinydns(':example.com:16:\\005ab:3600::\n'), /TXT: rdata is truncated/)
    const wire = Buffer.from('076578616d706c6503636f6d0000100001' + '00000e10' + '0004' + '05616263', 'hex')
    assert.throws(() => TXT.fromWire(wire), /TXT: rdata is truncated/)
  })
})

describe('TXT presentation-format escaping', function () {
  const rdata = (data) => txt(data).toBind().trimEnd().split('\t').slice(4).join('\t')
  const mara = (data) => txt(data).toMaraDNS()

  // RFC 1035 §5.1: an unescaped " would end the character-string early.
  for (const [data, expected] of [
    ['say "hi"', '"say \\"hi\\""'],
    ['c:\\path\\', '"c:\\\\path\\\\"'],
    ['a\\"b', '"a\\\\\\"b"'],
    ['v=spf1 -all', '"v=spf1 -all"'],
  ]) {
    it(`BIND: ${data}`, () => assert.equal(rdata(data), expected))
  }

  it('escapes each chunk of a value past 255 bytes', () => {
    const chunks = rdata('"'.repeat(300)).slice(1, -1).split('" "')
    assert.equal(chunks.length, 2, 'chunked on the unescaped length')
    for (const c of chunks) assert.doesNotMatch(c, /(^|[^\\])"/)
  })

  // csv2 quotes with ' and has its own rules, so payload " and \ stay as written.
  for (const [data, expected] of [
    ['v=spf1 mx -all', /^example\.com\.\t\+3600\tTXT\t'v=spf1 mx -all' ~\n$/],
    ['has "quotes" and \\ backslash', /'has "quotes" and \\ backslash'/],
    ["it's #1 ~ a|b\tc", /\t'it'\\x27's '\\x23'1 '\\x7e' a'\\x7c'b'\\x09'c' ~\n$/],
    ['y'.repeat(400), new RegExp(`\\tTXT\\t'${'y'.repeat(255)}';'${'y'.repeat(145)}' ~\\n$`)],
  ]) {
    it(`MaraDNS: ${data.slice(0, 30)}`, () => assert.match(mara(data), expected))
  }
})
