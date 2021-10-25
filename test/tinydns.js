
const assert = require('assert')

const TINYDNS = require('../lib/tinydns')

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
      it(`escapes tinydns rdata special char ${c}`, async function () {
        const e = TINYDNS.escapeOctal(rdataRe, c)
        assert.strictEqual(e, specialChars[c])
      })
    }
  })
})
