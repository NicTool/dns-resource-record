import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from './base.js'

import TXT from '../rr/txt.js'

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

    const r = new TXT({ tinyline: val.testT })
    if (process.env.DEBUG) console.dir(r)
    for (const f of r.getFields()) {
      if (f === 'class') continue
      assert.deepEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
    }
  })
})
