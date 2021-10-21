
const base = require('./index')

const validRecords = [
  {
    class  : 'IN',
    name   : 'test.example.com',
    type   : 'MX',
    address: 'mail.example.com.',
    weight : 0,
    ttl    : 3600,
  },
]

const invalidRecords = [
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

describe('MX record', function () {
  base.valid(validRecords)
  base.invalid(invalidRecords)
})
