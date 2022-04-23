
import assert from 'assert'

import * as TINYDNS from '../lib/tinydns.js'

describe('TINYDNS', function () {

  const b64cases = {
    '0sAQPeOwAGDPLrDebL1q5Lg8XW9B/d9MnxqlzIYKXhvZPWEHNYGP7AwART/tmkeDNn7HPMtgM6GIwQ4p0KGLfSRoUKbjtPlRVeWYLbsnNXeFU5bchyYef0efYiKlxZdo':
    '\\322\\300\\020\\075\\343\\260\\000\\140\\317.\\260\\336l\\275j\\344\\270\\074\\135oA\\375\\337L\\237\\032\\245\\314\\206\\012\\136\\033\\331\\075a\\0075\\201\\217\\354\\014\\000E\\077\\355\\232G\\2036\\176\\307\\074\\313\\1403\\241\\210\\301\\016\\051\\320\\241\\213\\175\\044hP\\246\\343\\264\\371QU\\345\\230-\\273\\0475w\\205S\\226\\334\\207\\046\\036\\177G\\237b\\042\\245\\305\\227h',
  }

  describe('base64toOctal', function () {
    for (const c in b64cases) {
      it('octal escapes a base64 encoded string', async function () {
        assert.strictEqual(TINYDNS.base64toOctal(c), b64cases[c])
      })
    }
  })

  describe('octalToBase64', function () {
    for (const c in b64cases) {
      it('converts octal escaped to base64 encoded string', async function () {
        assert.deepStrictEqual(TINYDNS.octalToBase64(b64cases[c]), c)
      })
    }
  })

  describe('escapeOctal', function () {

    const rdataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    it('escapes tinydns rdata special chars', async function () {
      const e = TINYDNS.escapeOctal(rdataRe, 'v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN/nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64/cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn/LAf+3kzW58AjsERpsNCSTD2RquxbnyoR/1wdGKb8cUlD/EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB')
      assert.strictEqual(e, 'v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN\\057nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64\\057cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn\\057LAf+3kzW58AjsERpsNCSTD2RquxbnyoR\\0571wdGKb8cUlD\\057EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB')
    })

    const specialChars = {
      '/' : '\\057',
      '\\': '\\134',
      ':' : '\\072',
    }

    for (const c of Object.keys(specialChars)) {
      it(`escapes tinydns rdata special char ${c}`, function () {
        assert.strictEqual(TINYDNS.escapeOctal(rdataRe, c), specialChars[c])
      })
    }
  })

  describe('octaltoChar', function () {
    it('converts a string of octal escapes to characters', async () => {
    })
  })

  describe('octalToHex', function () {
    it('unescapes octal to hex digits', function () {
      assert.strictEqual(TINYDNS.octalToHex('\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\001'), '00000000000000000000000000000001')
    })
  })

  describe('UInt16toOctal', function () {
    it('converts a 16-bit number to escaped octal', function () {
      assert.strictEqual(TINYDNS.UInt16toOctal(65535), '\\377\\377')
    })

    it('converts a 16-bit number to escaped octal', function () {
      assert.strictEqual(TINYDNS.UInt16toOctal(1), '\\000\\001')
    })
  })

  describe('octalToUInt16', function () {
    it('converts a 16-bit number to escaped octal', function () {
      assert.strictEqual(TINYDNS.octalToUInt16('\\377\\377'), 65535)
    })

    it('converts a 16-bit number to escaped octal', function () {
      assert.strictEqual(TINYDNS.octalToUInt16('\\000\\001'), 1)
    })
  })


  describe('UInt32toOctal', function () {
    it('converts a 32-bit number to escaped octal', function (done) {
      assert.strictEqual(TINYDNS.UInt32toOctal(2319310648), '\\212\\075\\337\\070')
      done()
    })

    it('converts a 32-bit number to escaped octal', function (done) {
      assert.strictEqual(TINYDNS.UInt32toOctal(1706988648), '\\145\\276\\224\\150')
      done()
    })
  })

  describe('octalToUInt32', function () {
    it('converts escaped octal to 32-bit integer', function () {
      assert.strictEqual(TINYDNS.octalToUInt32('\\145\\276\\224\\150'), 1706988648)
    })
  })

  describe('unpackDomainName', function () {
    it(`extracts domain name from wire format`, async () => {
      const r = TINYDNS.unpackDomainName('\\006sipdir\\006online\\004lync\\003com\\000')
      assert.strictEqual(r[0], 'sipdir.online.lync.com.')
      assert.strictEqual(r[1], 40)
    })
  })

  const cases = {
    '0.0.0.0'        : '\\000\\000\\000\\000',
    '192.0.2.127'    : '\\300\\000\\002\\177',
    '255.255.255.255': '\\377\\377\\377\\377',
  }

  describe('ipv4toOctal', function () {
    for (const c in cases) {
      it(`converts dotted quad IPv4 to octal escaped integer ${c}`, async () => {
        assert.strictEqual(TINYDNS.ipv4toOctal(c), cases[c])
      })
    }
  })

  describe('octalToIPv4', function () {
    for (const c in cases) {
      it(`converts octal escaped integer to dotted quad IPv4 ${cases[c]}`, async () => {
        assert.strictEqual(TINYDNS.octalToIPv4(cases[c]), c)
      })
    }
  })
})
