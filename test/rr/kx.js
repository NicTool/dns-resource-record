import { describe } from 'node:test'
import * as base from '../base.js'

import KX from '../../rr/kx.js'

const validRecords = [
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'KX',
    preference: 10,
    exchanger: 'kx.example.com.',
    testB: 'example.com.\t3600\tIN\tKX\t10\tkx.example.com.\n',
    testT: ':example.com:36:\\000\\012\\002kx\\007example\\003com\\000:3600::\n',
  },
  {
    owner: 'host.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'KX',
    preference: 0,
    exchanger: 'kx2.example.com.',
    testB: 'host.example.com.\t86400\tIN\tKX\t0\tkx2.example.com.\n',
    testT: ':host.example.com:36:\\000\\000\\003kx2\\007example\\003com\\000:86400::\n',
  },
  {
    owner: 'nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'KX',
    preference: 10,
    exchanger: 'kx.nictool.tnpi.net.',
    testB: 'nictool.tnpi.net.\t3600\tIN\tKX\t10\tkx.nictool.tnpi.net.\n',
    testT: ':nictool.tnpi.net:36:\\000\\012\\002kx\\007nictool\\004tnpi\\003net\\000:3600::\n',
    testW:
      '076e6963746f6f6c04746e7069036e6574000024000100000e100017000a026b78076e6963746f6f6c04746e7069036e657400',
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
  base.getCanonical(KX)
  base.getTypeId(KX, 36)
  base.getTags(KX)

  base.toBind(KX, validRecords)
  base.toWire(KX, validRecords)
  base.toTinydns(KX, validRecords)

  base.fromBind(KX, validRecords)
  base.fromTinydns(KX, validRecords)
})

base.fromWire(KX, validRecords)
