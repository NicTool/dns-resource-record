
const assert = require('assert')

const base = require('./base')

const SSHFP = require('../rr/sshfp')

const validRecords = [
  {
    class      : 'IN',
    name       : 'mail.example.com',
    type       : 'SSHFP',
    algorithm  : 1,
    fptype     : 1,
    fingerprint: 'ed8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26',
    ttl        : 86400,
    testR      : 'mail.example.com\t86400\t1\t1\ted8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26\n',
  },
]

const invalidRecords = [
]

describe('SSHFP record', function () {
  base.valid(SSHFP, validRecords)
  base.invalid(SSHFP, invalidRecords)

  for (const val of validRecords) {
    it('converts to BIND format', async function () {
      const r = new SSHFP(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it.skip('converts to tinydns format', async function () {
      const r = new SSHFP(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, ':_imaps._tcp.example.com:33:\\000\\001\\000\\000\\003\\341\\004mail\\007example\\003com\\000:3600::\n')
    })
  }
})
