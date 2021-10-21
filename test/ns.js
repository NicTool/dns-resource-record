
const base = require('./index')

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
  base.valid(validRecords)
  base.invalid(invalidRecords)
})
