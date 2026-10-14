import { describe } from 'node:test'
import * as base from '../base.js'

import RP from '../../rr/rp.js'

const valid = [
  {
    owner: 'example.com.',
    mbox: 'admin.example.com.',
    txt: 'info.example.com.',
    testB: 'example.com.\t3600\tIN\tRP\tadmin.example.com.\tinfo.example.com.\n',
    testT: ':example.com:17:\\005admin\\007example\\003com\\000\\004info\\007example\\003com\\000:3600::\n',
  },
  {
    owner: 'host.example.com.',
    ttl: 86400,
    mbox: 'hostmaster.example.com.',
    txt: '.',
    testB: 'host.example.com.\t86400\tIN\tRP\thostmaster.example.com.\t.\n',
    testT: ':host.example.com:17:\\012hostmaster\\007example\\003com\\000\\000:86400::\n',
  },
  {
    owner: 'nictool.tnpi.net.',
    mbox: 'hostmaster.tnpi.net.',
    txt: 'contact.nictool.tnpi.net.',
    testB: 'nictool.tnpi.net.\t3600\tIN\tRP\thostmaster.tnpi.net.\tcontact.nictool.tnpi.net.\n',
    testT:
      ':nictool.tnpi.net:17:\\012hostmaster\\004tnpi\\003net\\000\\007contact\\007nictool\\004tnpi\\003net\\000:3600::\n',
    testW:
      '076e6963746f6f6c04746e7069036e6574000011000100000e10002f0a686f73746d617374657204746e7069036e65740007636f6e74616374076e6963746f6f6c04746e7069036e657400',
  },
]

const invalid = [
  {
    owner: 'example.com.',
    mbox: '',
    txt: 'info.example.com.',
    msg: /mbox is required/,
  },
  {
    owner: 'example.com.',
    mbox: 'admin.example.com.',
    txt: '',
    msg: /txt is required/,
  },
  {
    owner: 'example.com.',
    mbox: 'admin.example.com',
    txt: 'info.example.com.',
    msg: /mbox must be fully qualified/,
  },
]

describe('RP record', function () {
  base.suite(RP, { typeId: 17, fields: ['mbox', 'txt'], valid, invalid })
})
