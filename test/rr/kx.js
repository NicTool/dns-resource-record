import { describe } from 'node:test'
import * as base from '../base.js'

import KX from '../../rr/kx.js'

const valid = [
  {
    owner: 'example.com.',
    preference: 10,
    exchanger: 'kx.example.com.',
    testB: 'example.com.\t3600\tIN\tKX\t10\tkx.example.com.\n',
    testT: ':example.com:36:\\000\\012\\002kx\\007example\\003com\\000:3600::\n',
  },
  {
    owner: 'host.example.com.',
    ttl: 86400,
    preference: 0,
    exchanger: 'kx2.example.com.',
    testB: 'host.example.com.\t86400\tIN\tKX\t0\tkx2.example.com.\n',
    testT: ':host.example.com:36:\\000\\000\\003kx2\\007example\\003com\\000:86400::\n',
  },
  {
    owner: 'nictool.tnpi.net.',
    preference: 10,
    exchanger: 'kx.nictool.tnpi.net.',
    testB: 'nictool.tnpi.net.\t3600\tIN\tKX\t10\tkx.nictool.tnpi.net.\n',
    testT: ':nictool.tnpi.net:36:\\000\\012\\002kx\\007nictool\\004tnpi\\003net\\000:3600::\n',
    testW:
      '076e6963746f6f6c04746e7069036e6574000024000100000e100017000a026b78076e6963746f6f6c04746e7069036e657400',
  },
]

const invalid = [
  ['preference', undefined, /preference is required/],
  ['exchanger', '', /exchanger is required/],
  ['exchanger', 'kx.example.com', /exchanger must be fully qualified/],
].map(([f, v, msg]) => ({ ...valid[0], [f]: v, msg }))

describe('KX record', function () {
  base.suite(KX, {
    typeId: 36,
    fields: ['preference', 'exchanger'],
    valid,
    invalid,
  })
})
