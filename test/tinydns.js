
import assert from 'assert'

import * as TINYDNS from '../lib/tinydns.js'

describe('TINYDNS', function () {

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
        const e = TINYDNS.escapeOctal(rdataRe, c)
        assert.strictEqual(e, specialChars[c])
      })
    }
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
})
