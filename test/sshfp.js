
const assert = require('assert')

const base = require('./base')

const SSHFP = require('../rr/sshfp')

const validRecords = [
  {
    class      : 'IN',
    type       : 'SSHFP',
    name       : 'mail.example.com',
    algorithm  : 1,
    fptype     : 1,
    fingerprint: 'ed8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26',
    ttl        : 86400,
    testR      : 'mail.example.com\t86400\t1\t1\ted8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26\n',
    testT      : ':mail.example.com:44:\\000\\001\\000\\001\\355\\214\\156\\026\\375\\256\\117\\143\\076\\356\\152\\173\\217\\144\\375\\323\\126\\273\\263\\050\\101\\325\\065\\126\\135\\167\\160\\024\\311\\352\\114\\046:86400::\n',
  },
]

const invalidRecords = [
]

describe.only('SSHFP record', function () {
  base.valid(SSHFP, validRecords)
  base.invalid(SSHFP, invalidRecords)

  base.toBind(SSHFP, validRecords)
  base.toTinydns(SSHFP, validRecords)

  for (const val of validRecords) {
    it(`imports tinydns SSHFP (generic) record`, async function () {
      const r = new SSHFP({ tinyline: val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of [ 'name', 'algorithm', 'fptype', 'fingerprint', 'ttl' ]) {
        assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
      }
    })
  }
})
