
const assert = require('assert')

const ResourceRecord = require('../index.js')

const validRecords = [
  {
    class  : 'IN',
    name   : 'example.com',
    type   : 'SOA',
    mname  : 'matt.example.com.',
    rname  : 'ns1.example.com.',
    serial : 1,
    refresh: 7200,
    retry  : 3600,
    expire : 1209600,
    ttl    : 3600,
  },
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'A',
    address: '127.0.0.127',
    ttl    : 3600,
  },
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'MX',
    address: 'mail.example.com.',
    weight : 0,
    ttl    : 3600,
  },
  {
    class  : 'IN',
    name   : 'example.com',
    type   : 'NS',
    address: 'ns1.example.com.',
    ttl    : 3600,
  },
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'AAAA',
    address: '2605:7900:20:a::4',
    ttl    : 3600,
  },
  {
    name   : 'oct2021._domainkey.example.com',
    type   : 'TXT',
    address: 'v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoyUzGOTSOmakY8BcxXgi0mN/nFegLBPs7aaGQUtjHfa8yUrt9T2j6GSXgdjLuG3R43WjePQv3RHzc+bwwOkdw0XDOXiztn5mhrlaflbVr5PMSTrv64/cpFQKLtgQx8Vgqp7Dh3jw13rLomRTqJFgMrMHdhIibZEa69gtuAfDqoeXo6QDSGk5JuBAeRHEH27FriHulg5ob4F4lmh7fMFVsDGkQEF6jaIVYqvRjDyyQed3R3aTJX3fpb3QrtRqvfn/LAf+3kzW58AjsERpsNCSTD2RquxbnyoR/1wdGKb8cUlD/EXvqtvpVnOzHeSeMEqex3kQI8HOGsEehWZlKd+GqwIDAQAB',
    ttl    : 86400,
  },
]

const invalidRecords = [
  {
    class  : 'IN',
    name   : 'example.com',
    type   : 'SOA',
    mname  : 'matt.example.com.',
    rname  : 'ns1.example.com.',
    serial : 4294967296,
    refresh: 7200,
    retry  : 3600,
    expire : 1209600,
    ttl    : 3600,
  },
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'A',
    address: 'hosts.not.valid.here',
    ttl    : 3600,
  },
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'MX',
    address: 'not-full-qualified.example.com',
    ttl    : 3600,
  },
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'MX',
    address: '192.168.0.1',
    ttl    : 3600,
  },
]

describe('resource-record', function () {

  for (const val of validRecords) {
    // console.log(val)
    it(`parses valid ${val.type} record`, async function () {
      const r = new ResourceRecord[val.type](val)
      if (process.env.DEBUG) console.dir(r)

      for (const k of Object.keys(val)) {
        assert.strictEqual(r.get(k), val[k], `${k} ${r.get(k)} !== ${val[k]}`)
      }
    })
  }

  for (const inv of invalidRecords) {

    const ucType = inv.type.toUpperCase()

    it(`throws on invalid ${ucType} record`, async function () {
      try {
        new ResourceRecord[ucType](inv)
      }
      catch (e) {
        if (process.env.DEBUG) console.error(e.message)
        assert.ok(e)
        return
      }
      throw new Error(`failed to throw`)
    })
  }
})