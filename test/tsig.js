import { describe } from 'node:test'

import * as base from './base.js'

import TSIG from '../rr/tsig.js'

const defaults = { class: 'IN', ttl: 3600, type: 'TSIG' }

const validRecords = [
  {
    ...defaults,
    owner: 'test.example.',
    'algorithm name': 'SAMPLE-ALG.EXAMPLE.',
    'time signed': 853804800,
    fudge: 300,
    'mac size': 0,
    mac: '',
    'original id': 0,
    error: 0,
    other: '',
    testB: 'test.example.\t3600\tIN\tTSIG\tSAMPLE-ALG.EXAMPLE.\t853804800\t300\t0\t\t0\t0\n',
    testT:
      ':test.example:250:\\012SAMPLE-ALG\\007EXAMPLE\\000\\062\\344\\007\\000\\001\\054\\000\\000\\000\\000\\000\\000:3600::\n',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'test.example.',
    // missing algorithm name
    'time signed': 853804800,
    msg: /algorithm name/i,
  },
  {
    ...defaults,
    owner: 'test.example.',
    'algorithm name': 'SAMPLE-ALG.EXAMPLE.',
    // missing time signed
    msg: /time signed/i,
  },
  {
    ...defaults,
    owner: 'not-fqdn',
    'algorithm name': 'SAMPLE-ALG.EXAMPLE.',
    'time signed': 853804800,
    msg: /must be fully qualified/i,
  },
]

describe('TSIG record', function () {
  base.valid(TSIG, validRecords)
  base.invalid(TSIG, invalidRecords)

  base.getDescription(TSIG)
  base.getRFCs(TSIG, validRecords[0])
  base.getFields(TSIG, [
    'algorithm name',
    'time signed',
    'fudge',
    'mac size',
    'mac',
    'original id',
    'error',
    'other',
  ])
  base.getTypeId(TSIG, 250)

  base.toBind(TSIG, validRecords)
  base.toTinydns(TSIG, validRecords)

  base.fromBind(TSIG, validRecords)
  //   base.fromTinydns(TSIG, validRecords)
})
