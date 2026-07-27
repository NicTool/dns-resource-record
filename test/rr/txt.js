import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import TXT from '../../rr/txt.js'

const validRecords = [
  {
    owner: 'oct2021._domainkey.example.com.',
    ttl: 86400,
    type: 'TXT',
    data: 'v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN/nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64/cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn/LAf+3kzW58AjsERpsNCSTD2RquxbnyoR/1wdGKb8cUlD/EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB',
    testB:
      'oct2021._domainkey.example.com.\t86400\tIN\tTXT\t"v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN/nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64/cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob" "4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn/LAf+3kzW58AjsERpsNCSTD2RquxbnyoR/1wdGKb8cUlD/EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB"\n',
    testT:
      "'oct2021._domainkey.example.com:v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN\\057nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64\\057cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn\\057LAf+3kzW58AjsERpsNCSTD2RquxbnyoR\\0571wdGKb8cUlD\\057EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB:86400::\n",
    testW:
      '076f6374323032310a5f646f6d61696e6b6579076578616d706c6503636f6d0000100001000151800194ff763d444b494d313b703d4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b43415145416f79557a474f54534f6d616b5938426378586769306d4e2f6e4665674c425073376161475155746a48666138795572743954326a3647535867646a4c754733523433576a655051763352487a632b6277774f6b64773058444f58697a746e356d68726c61666c62567235504d5354727636342f637046514b4c746751783856677170374468336a773133724c6f6d5254714a46674d724d4864684969625a45613639677475416644716f65586f36514453476b354a7542416552484548323746726948756c67356f62933446346c6d6837664d46567344476b514546366a614956597176526a44797951656433523361544a583366706233517274527176666e2f4c41662b336b7a573538416a73455270734e435354443252717578626e796f522f317764474b623863556c442f45587671747670566e4f7a486553654d45716578336b514938484f4773456568575a6c4b642b477177494441514142',
  },
  {
    owner: 'oct2021._domainkey.example.com.',
    ttl: 86400,
    type: 'TXT',
    data: [
      'v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN/nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64/cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob',
      '4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn/LAf+3kzW58AjsERpsNCSTD2RquxbnyoR/1wdGKb8cUlD/EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB',
    ],
    testB:
      'oct2021._domainkey.example.com.\t86400\tIN\tTXT\t"v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN/nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64/cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob" "4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn/LAf+3kzW58AjsERpsNCSTD2RquxbnyoR/1wdGKb8cUlD/EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB"\n',
    testT:
      "'oct2021._domainkey.example.com:v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN\\057nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64\\057cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn\\057LAf+3kzW58AjsERpsNCSTD2RquxbnyoR\\0571wdGKb8cUlD\\057EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB:86400::\n",
    testW:
      '076f6374323032310a5f646f6d61696e6b6579076578616d706c6503636f6d0000100001000151800194ff763d444b494d313b703d4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b43415145416f79557a474f54534f6d616b5938426378586769306d4e2f6e4665674c425073376161475155746a48666138795572743954326a3647535867646a4c754733523433576a655051763352487a632b6277774f6b64773058444f58697a746e356d68726c61666c62567235504d5354727636342f637046514b4c746751783856677170374468336a773133724c6f6d5254714a46674d724d4864684969625a45613639677475416644716f65586f36514453476b354a7542416552484548323746726948756c67356f62933446346c6d6837664d46567344476b514546366a614956597176526a44797951656433523361544a583366706233517274527176666e2f4c41662b336b7a573538416a73455270734e435354443252717578626e796f522f317764474b623863556c442f45587671747670566e4f7a486553654d45716578336b514938484f4773456568575a6c4b642b477177494441514142',
  },
  {
    owner: 'example.com.',
    ttl: 86400,
    type: 'TXT',
    data: 'v=spf1 mx a include:mx.example.com -all',
    testB: 'example.com.\t86400\tIN\tTXT\t"v=spf1 mx a include:mx.example.com -all"\n',
    testT: "'example.com:v=spf1 mx a include\\072mx.example.com -all:86400::\n",
    testW:
      '076578616d706c6503636f6d000010000100015180002827763d73706631206d78206120696e636c7564653a6d782e6578616d706c652e636f6d202d616c6c',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'TXT',
    data: ['v=spf1 mx include:tnpi.net -all'],
    testB: 'nictool.tnpi.net.\t3600\tIN\tTXT\t"v=spf1 mx include:tnpi.net -all"\n',
    testT: "'nictool.tnpi.net:v=spf1 mx include\\072tnpi.net -all:3600::\n",
    testW:
      '076e6963746f6f6c04746e7069036e6574000010000100000e1000201f763d73706631206d7820696e636c7564653a746e70692e6e6574202d616c6c',
  },
]

const invalidRecords = []

describe('TXT record', function () {
  base.valid(TXT, validRecords)
  base.invalid(TXT, invalidRecords)

  base.getDescription(TXT)
  base.getRFCs(TXT, validRecords[0])
  base.getFields(TXT, ['data'])
  base.getCanonical(TXT)
  base.getTypeId(TXT, 16)
  base.getTags(TXT)

  base.toBind(TXT, validRecords)
  base.toWire(TXT, validRecords)
  base.toTinydns(TXT, validRecords)

  base.fromTinydns(TXT, validRecords)
  base.fromBind(TXT, validRecords)
  base.fromWire(TXT, validRecords)

  it(`toBind chunks non-ASCII TXT data by UTF-8 bytes, not characters`, function () {
    // 200 × "é" = 200 chars but 400 UTF-8 bytes → must split into multiple
    // 255-byte character-strings. Char-based chunking would emit a single
    // 400-byte token, which BIND named rejects.
    const data = 'é'.repeat(200)
    const r = new TXT({ owner: 'example.com.', ttl: 3600, class: 'IN', type: 'TXT', data }).toBind()
    const quoted = r.match(/"([^"]*)"/g)
    assert.ok(quoted.length > 1, `expected multiple quoted chunks, got: ${r}`)
    for (const q of quoted) {
      const inner = q.slice(1, -1)
      const bytes = new TextEncoder().encode(inner).length
      assert.ok(bytes <= 255, `chunk exceeds 255 bytes (${bytes}): ${inner}`)
    }
    // Content round-trips: concatenated chunks equal original data
    assert.equal(quoted.map((q) => q.slice(1, -1)).join(''), data)
  })

  it(`imports tinydns TXT (generic) record`, async function () {
    const val = {
      owner: 'nov2021._domainkey.example.com.',
      type: 'TXT',
      data: 'v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN/nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64/cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn/LAf+3kzW58AjsERpsNCSTD2RquxbnyoR/1wdGKb8cUlD/EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB',
      ttl: 86400,
      testB:
        'nov2021._domainkey.example.com.\t86400\tIN\tTXT\t"v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN/nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64/cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob" "4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn/LAf+3kzW58AjsERpsNCSTD2RquxbnyoR/1wdGKb8cUlD/EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB"\n',
      testT:
        ':nov2021._domainkey.example.com:16:\\622v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN\\057nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64\\057cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn\\057LAf+3kzW58AjsERpsNCSTD2RquxbnyoR\\0571wdGKb8cUlD\\057EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB:86400\n',
    }

    const r = TXT.fromTinydns(val.testT)
    if (process.env.DEBUG) console.dir(r)
    for (const f of r.getFields()) {
      if (f === 'class') continue
      assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
    }
  })

  it('exports TXT record in MaraDNS format', function () {
    const r = new TXT({ owner: 'example.com.', ttl: 3600, class: 'IN', type: 'TXT', data: 'v=spf1 mx -all' })
    assert.equal(r.toMaraDNS(), "example.com.\t+3600\tTXT\t'v=spf1 mx -all' ~\n")
  })

  // RFC 1035 §3.3.14: multi-string TXT records are wire-distinct from one
  // concatenated string. Boundaries must round-trip through encode/decode.
  describe('multi-string boundary preservation', function () {
    const owner = 'example.com.'
    const segments = ['hello', 'world']

    it('encodes array as N len-prefixed character-strings on the wire', function () {
      const r = new TXT({ owner, ttl: 3600, class: 'IN', type: 'TXT', data: segments })
      const rdata = r.getWireRdata()
      // Expect [5, h, e, l, l, o, 5, w, o, r, l, d]
      assert.deepEqual([...rdata], [5, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 5, 0x77, 0x6f, 0x72, 0x6c, 0x64])
    })

    it('decodes multi-string wire form back to array', function () {
      const r = new TXT({ owner, ttl: 3600, class: 'IN', type: 'TXT', data: segments })
      const wire = r.toWire()
      const r2 = TXT.fromWire(wire)
      assert.deepEqual(r2.get('data'), segments)
    })

    it('decodes a single-string wire form back to a plain string', function () {
      const r = new TXT({ owner, ttl: 3600, class: 'IN', type: 'TXT', data: 'just one' })
      const r2 = TXT.fromWire(r.toWire())
      assert.equal(r2.get('data'), 'just one')
    })

    it('fromBind on "a" "b" returns the array form', function () {
      const bindline = 'example.com.\t3600\tIN\tTXT\t"hello" "world"\n'
      const r = TXT.fromBind(bindline)
      assert.deepEqual(r.get('data'), segments)
    })

    it('rejects an array element longer than 255 bytes (boundary not preservable)', function () {
      const r = new TXT({
        owner,
        ttl: 3600,
        class: 'IN',
        type: 'TXT',
        data: ['ok', 'x'.repeat(256)],
      })
      assert.throws(() => r.getWireRdata(), /exceeds 255 bytes/)
    })

    it('fromTinydnsGeneric rejects a truncated len-prefixed segment', function () {
      // tinydns generic with declared length 5 but only 2 trailing bytes.
      // Use octal escape so the length byte survives the tinydns parser.
      const truncated = ':example.com:16:\\005ab:3600::\n'
      assert.throws(() => new TXT(null).fromTinydnsGeneric(truncated), /truncated character-string/)
    })

    it('fromWire rejects a truncated charstr in rdata', function () {
      // Hand-craft a wire record whose final character-string length byte
      // claims more bytes than remain in rdata.
      // owner = "example.com." (uncompressed), type 16, class 1, ttl 3600,
      // rdlen 4, then rdata = [\x05 a b c] (declared 5, only 3 follow).
      const wire = Buffer.concat([
        Buffer.from([7]),
        Buffer.from('example'),
        Buffer.from([3]),
        Buffer.from('com'),
        Buffer.from([0]),
        Buffer.from([0x00, 0x10]), // type 16
        Buffer.from([0x00, 0x01]), // class 1
        Buffer.from([0x00, 0x00, 0x0e, 0x10]), // ttl 3600
        Buffer.from([0x00, 0x04]), // rdlen 4
        Buffer.from([5, 0x61, 0x62, 0x63]), // declared len 5, only 3 chars
      ])
      assert.throws(() => TXT.fromWire(wire), /truncated character-string/)
    })
  })
})

describe('TXT presentation-format escaping', function () {
  const txt = (data) => new TXT({ owner: 'esc.example.com.', ttl: 300, class: 'IN', data })
  const rdata = (rr) => rr.toBind().trimEnd().split('\t').slice(4).join('\t')

  it('escapes double quotes inside a character-string', () => {
    // RFC 1035 §5.1: an unescaped " would end the character-string early,
    // which BIND and every other parser rejects.
    assert.equal(rdata(txt('say "hi"')), '"say \\"hi\\""')
  })

  it('escapes backslashes', () => {
    assert.equal(rdata(txt('c:\\path\\')), '"c:\\\\path\\\\"')
  })

  it('escapes both, in order, without double-escaping', () => {
    assert.equal(rdata(txt('a\\"b')), '"a\\\\\\"b"')
  })

  it('escapes each chunk of a value past 255 bytes', () => {
    const rr = txt('"'.repeat(300))
    const chunks = rdata(rr).slice(1, -1).split('" "')

    assert.equal(chunks.length, 2, 'chunked on the unescaped length')
    for (const c of chunks) {
      assert.doesNotMatch(c, /(^|[^\\])"/, 'no bare quote survives in any chunk')
    }
  })

  it('leaves ordinary data untouched', () => {
    assert.equal(rdata(txt('v=spf1 -all')), '"v=spf1 -all"')
  })

  it('does not apply RFC 1035 escaping to MaraDNS output', () => {
    // csv2 quotes with ' and has its own rules; escaping here would change the
    // payload rather than its presentation.
    const out = txt('has "quotes" and \\ backslash').toMaraDNS()

    assert.match(out, /'has "quotes" and \\ backslash'/)
    assert.doesNotMatch(out, /\\"/)
  })

  it('leaves payload quotes alone, quoting only the csv2 chunk delimiter', () => {
    // Rewriting every " to ' also hit the payload, which both corrupts the
    // value and unbalances the surrounding '...' quoting.
    assert.match(txt('a "b" c').toMaraDNS(), /'a "b" c'/)
  })

  it('joins chunked MaraDNS output with the csv2 delimiter', () => {
    const out = txt('y'.repeat(400)).toMaraDNS()

    assert.match(out, /' '/, "chunks are separated by ' '")
    assert.doesNotMatch(out, /"/, 'no RFC 1035 quoting leaks into csv2')
  })
})
