
const base = require('./index')

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
]

describe('SOA record', function () {
  base.valid(validRecords)
  base.invalid(invalidRecords)
})