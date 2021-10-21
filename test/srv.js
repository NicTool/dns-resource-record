
const assert = require('assert')

const base = require('./base')

const SRV = require('../rr/srv')

const validRecords = [
  {
    class   : 'IN',
    name    : '_imaps._tcp.example.com',
    type    : 'SRV',
    target  : 'mail.example.com.',
    priority: 1,
    weight  : 0,
    port    : 993,
    ttl     : 3600,
    testR   : '_imaps._tcp.example.com\t3600\tIN\tSRV\t1\t0\t993\tmail.example.com.\n',
  },
]

const invalidRecords = [
  {
    class : 'IN',
    name  : 'test.example.com',
    type  : 'SRV',
    target: 'not-full-qualified.example.com',
    ttl   : 3600,
  },
  {
    class : 'IN',
    name  : 'test.example.com',
    type  : 'SRV',
    target: '192.168.0.1',
    ttl   : 3600,
  },
]

describe('SRV record', function () {
  base.valid(SRV, validRecords)
  base.invalid(SRV, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new SRV(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it('converts to tinydns format', async function () {
      const r = new SRV(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, ':_imaps._tcp.example.com:33:\\000\\001\\000\\000\\003\\341\\004mail\\007example\\003com\\000:3600::\n')
    })
  }
})
