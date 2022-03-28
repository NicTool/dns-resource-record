
// const assert = require('assert')

const A    = require('../rr/a.js')
const base = require('./base')

const validRecords = [
  {
    owner  : 'test.example.com.',
    ttl    : 3600,
    class  : 'IN',
    type   : 'A',
    address: '192.0.2.127',
    testB  : 'test.example.com.\t3600\tIN\tA\t192.0.2.127\n',
    testT  : '+test.example.com:192.0.2.127:3600::\n',
  },
  {
    owner  : 'test.example.com.',
    ttl    : 2147483647,
    class  : 'IN',
    type   : 'A',
    address: '192.0.2.127',
    testB  : 'test.example.com.\t2147483647\tIN\tA\t192.0.2.127\n',
    testT  : '+test.example.com:192.0.2.127:2147483647::\n',
  },
  {
    owner  : 'a.',
    ttl    : 86400,
    class  : 'IN',
    type   : 'A',
    address: '192.0.2.127',
    testB  : 'a.\t86400\tIN\tA\t192.0.2.127\n',
    testT  : '+a:192.0.2.127:86400::\n',
  },
]

const moreValid = [
  {
    owner: '*.example.com.',
    testB: '*.example.com.\t3600\tIN\tA\t192.0.2.127\n',
    testT: '+*.example.com:192.0.2.127:3600::\n',
  },
]

for (let i = 0; i < moreValid.length; i++) {
  const temp = JSON.parse(JSON.stringify(validRecords[0]))
  Object.assign(temp, moreValid[i])
  validRecords.push(temp)
}

const invalidRecords = [
  { owner: '' },
  { owner: 'something*' },
  { owner: 'some*thing' },
  { owner: '*something' },
  { owner: 'something.*' },
  { owner: 'a.m.' },
  { owner: 'something.test.' },
  { address: 'hosts.not.valid.here' },
  { address: '' },
  { address: undefined },
  { address: '1.x.2.3' },
  { address: '.1.2.3' },
  { address: '0.0.0.0' },
  { type: '' },
  { type: undefined },
  { ttl: ''   },
  { ttl: -299 },
  { ttl: 2147483648 },
]

// copy invalid properties to a valid object
for (let i = 0; i < invalidRecords.length; i++) {
  const temp = JSON.parse(JSON.stringify(validRecords[0]))
  Object.assign(temp, invalidRecords[i])
  invalidRecords[i] = temp
}

describe('A record', function () {
  base.valid(A, validRecords)
  base.invalid(A, invalidRecords)

  base.getDescription(A)
  base.getRFCs(A, validRecords[0])
  base.getFields(A, [ 'address' ])
  base.getTypeId(A, 1)

  base.toBind(A, validRecords)
  base.toTinydns(A, validRecords)

  base.fromBind(A, validRecords)
  base.fromTinydns(A, validRecords)
})
