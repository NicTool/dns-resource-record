
// const assert = require('assert')

const A    = require('../rr/a.js')
const base = require('./base')

const defaults = { class: 'IN', ttl: 3600, type: 'A', address: '192.0.2.127' }

const validRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    testB: 'test.example.com.\t3600\tIN\tA\t192.0.2.127\n',
    testT: '+test.example.com:192.0.2.127:3600::\n',
  },
  {
    ...defaults,
    owner: 'test.example.com.',
    ttl  : 2147483647,
    testB: 'test.example.com.\t2147483647\tIN\tA\t192.0.2.127\n',
    testT: '+test.example.com:192.0.2.127:2147483647::\n',
  },
  {
    ...defaults,
    owner: 'a.',
    ttl  : 86400,
    testB: 'a.\t86400\tIN\tA\t192.0.2.127\n',
    testT: '+a:192.0.2.127:86400::\n',
  },
  {
    ...defaults,
    owner: '*.example.com.',
    testB: '*.example.com.\t3600\tIN\tA\t192.0.2.127\n',
    testT: '+*.example.com:192.0.2.127:3600::\n',
  },
]

const invalidRecords = [
  { ...defaults, owner: '', msg: /RFC/ },
  { ...defaults, owner: 'something*', msg: /fully/ },
  { ...defaults, owner: 'some*thing', msg: /fully/ },
  { ...defaults, owner: '*something', msg: /fully/ },
  { ...defaults, owner: 'something.*', msg: /fully/ },
  { ...defaults, address: 'hosts.not.valid.here', msg: /address must be IPv4/ },
  { ...defaults, address: '', msg: /address is required/ },
  { ...defaults, address: undefined, msg: /address is required/ },
  { ...defaults, address: '1.x.2.3', msg: /address must be IPv4/ },
  { ...defaults, address: '.1.2.3', msg: /address must be IPv4/ },
  { ...defaults, type: '', msg: /not supported/ },
  { ...defaults, type: undefined, msg: /type undefined not supported/ },
  { ...defaults, ttl: '', msg: /TTL must be numeric/ },
  { ...defaults, ttl: -299, msg: /TTL must be a 32-bit integer/ },
  { ...defaults, ttl: 2147483648, msg: /TTL must be a 32-bit integer/ },
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
  base.getRdataFields(A, [ 'address' ])
  base.getFields(A, [ 'address' ])
  base.getTypeId(A, 1)

  base.toBind(A, validRecords)
  base.toTinydns(A, validRecords)

  base.fromBind(A, validRecords)
  base.fromTinydns(A, validRecords)
})
