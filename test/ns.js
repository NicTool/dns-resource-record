
const assert = require('assert')

const base = require('./base')

const NS = require('../rr/ns')

const validRecords = [
  {
    class  : 'IN',
    name   : 'example.com',
    type   : 'NS',
    address: 'ns1.example.com.',
    ttl    : 3600,
  },
]

const invalidRecords = [
]

describe('NS record', function () {
  base.valid(NS, validRecords)
  base.invalid(NS, invalidRecords)
})
