import * as base from './base.js'

import KX from '../rr/kx.js'

const validRecords = [
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'KX',
    preference: 10,
    exchanger: 'kx.example.com.',
    testB: 'example.com.\t3600\tIN\tKX\t10\tkx.example.com.\n',
  },
  {
    owner: 'host.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'KX',
    preference: 0,
    exchanger: 'kx2.example.com.',
    testB: 'host.example.com.\t86400\tIN\tKX\t0\tkx2.example.com.\n',
  },
]

const invalidRecords = [
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'KX',
    preference: undefined,
    exchanger: 'kx.example.com.',
    msg: /preference is required/,
  },
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'KX',
    preference: 10,
    exchanger: '',
    msg: /exchanger is required/,
  },
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'KX',
    preference: 10,
    exchanger: 'kx.example.com',
    msg: /exchanger must be fully qualified/,
  },
]

describe('KX record', function () {
  base.valid(KX, validRecords)
  base.invalid(KX, invalidRecords)

  base.getDescription(KX)
  base.getRFCs(KX, validRecords[0])
  base.getFields(KX, ['preference', 'exchanger'])
  base.getTypeId(KX, 36)

  base.toBind(KX, validRecords)

  base.fromBind(KX, validRecords)
})
