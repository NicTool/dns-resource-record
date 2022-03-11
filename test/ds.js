
// const assert = require('assert')

const base = require('./base')

const DS = require('../rr/ds')

const validRecords = [
  // {
  //   class     : 'IN',
  //   name      : 'dskey.example.com',
  //   type      : 'DNSKEY',
  //   keytag    : 256,
  //   algorithm : 3,
  //   digesttype: 5,
  //   digest    : `( AQOeiiR0GOMYkDshWoSKz9Xz\n\t\tfwJr1AYtsmx3TGkJaNXVbfi/\n\t\t2pHm822aJ5iI9BMzNXxeYCmZ\n\t\tDRD99WYwYqUSdjMmmAphXdvx\n\t\tegXd/M5+X7OrzKBaMbCVdFLU\n\t\tUh6DhweJBjEVv5f2wwjM9Xzc\n\t\tnOf+EPbtG9DMBmADjFDc2w/r\n\t\tljwvFw==\n\t\t) ;  key id = 60485`,
  //   ttl       : 3600,
  //   testB     : '_imaps._tcp.example.com\t3600\tIN\tDS\t1\t0\t993\tmail.example.com.\n',
  //   testT     : ':_imaps._tcp.example.com:33:\\000\\001\\000\\000\\003\\341\\004mail\\007example\\003com\\000:3600::\n',
  // },
  {
    class     : 'IN',
    name      : 'dskey.example.com',
    type      : 'DS',
    keytag    : 60485,
    algorithm : 5,
    digesttype: 1,
    digest    : `( 2BB183AF5F22588179A53B0A 98631FAD1A292118 )`,
    ttl       : 3600,
    testB     : 'dskey.example.com\t3600\tIN\tDS\t60485\t5\t1\t( 2BB183AF5F22588179A53B0A 98631FAD1A292118 )\n',
    testT     : ':_imaps._tcp.example.com:33:\\000\\001\\000\\000\\003\\341\\004mail\\007example\\003com\\000:3600::\n',
  },
]

const invalidRecords = [
  {
    name     : 'test.example.com',
    class    : 'IN',
    type     : 'DS',
    ttl      : 3600,
    algorithm: 6,  // invalid
  },
]

describe('DS record', function () {
  base.valid(DS, validRecords)
  base.invalid(DS, invalidRecords)

  base.getDescription(DS)
  base.getRFCs(DS, validRecords[0])
  base.getFields(DS, [ 'keytag', 'algorithm', 'digesttype', 'digest' ])
  base.getTypeId(DS, 43)

  base.toBind(DS, validRecords)
  // base.toTinydns(DS, validRecords)

  base.fromBind(DS, validRecords)
  // base.fromTinydns(DS, validRecords)

  // for (const val of validRecords) {
  //   it(`imports tinydns DS (generic) record (${val.name})`, async function () {
  //     const r = new DS({ tinyline: val.testT })
  //     if (process.env.DEBUG) console.dir(r)
  //     for (const f of [ 'name', 'target', 'priority', 'weight', 'port', 'ttl' ]) {
  //       assert.deepStrictEqual(r.get(f), val[f], `${f}: ${r.get(f)} !== ${val[f]}`)
  //     }
  //   })
  // }
})
