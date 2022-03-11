
// const assert = require('assert')

const base = require('./base')

const DS = require('../rr/ds')

const validRecords = [
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
    algorithm: 6,  // invalid
  },
]

describe('DS record', function () {
  base.valid(DS, validRecords)
  base.invalid(DS, invalidRecords, { ttl: 3600 })

  base.getDescription(DS)
  base.getRFCs(DS, validRecords[0])
  base.getFields(DS, [ 'keytag', 'algorithm', 'digesttype', 'digest' ])
  base.getTypeId(DS, 43)

  base.toBind(DS, validRecords)
  // base.toTinydns(DS, validRecords)

  base.fromBind(DS, validRecords)
  // base.fromTinydns(DS, validRecords)
})
