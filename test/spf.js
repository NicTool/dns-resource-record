
// const assert = require('assert')

const base = require('./base')

const SPF = require('../rr/spf')

const validRecords = [
  {
    name : 'example.com',
    type : 'SPF',
    data : 'v=spf1 mx a include:mx.example.com -all',
    ttl  : 86400,
    testR: 'example.com\t86400\tIN\tSPF\t"v=spf1 mx a include:mx.example.com -all"\n',
    testT: 'example.com:99:v=spf1 mx a include\\072mx.example.com -all:86400::\n',
  },
]

const invalidRecords = [
]

describe('SPF record', function () {
  base.valid(SPF, validRecords)
  base.invalid(SPF, invalidRecords)

  base.toBind(SPF, validRecords)
  base.toTinydns(SPF, validRecords)
})