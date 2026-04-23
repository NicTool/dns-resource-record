import { describe } from 'node:test'

import * as base from '../base.js'

import TSIG from '../../rr/tsig.js'

const defaults = { class: 'ANY', ttl: 0, type: 'TSIG' }

const validRecords = [
  {
    ...defaults,
    owner: 'test.example.',
    'algorithm name': 'SAMPLE-ALG.EXAMPLE.',
    'time signed': 853804800,
    fudge: 300,
    mac: '',
    'original id': 0,
    error: 0,
    other: '',
    testB: 'test.example.\t0\tANY\tTSIG\tSAMPLE-ALG.EXAMPLE.\t853804800\t300\t\t\t0\t0\t0\n',
    testT:
      ':test.example:250:\\012SAMPLE-ALG\\007EXAMPLE\\000\\062\\344\\007\\000\\001\\054\\000\\000\\000\\000\\000\\000:0::\n',
    testW:
      '0474657374076578616d706c650000fa00ff0000000000200a53414d504c452d414c47074558414d504c450032e40700012c000000000000',
  },
  {
    ...defaults,
    owner: 'test.example.',
    'algorithm name': 'HMAC-SHA256.',
    'time signed': 853804800,
    fudge: 300,
    mac: 'deadbeef',
    'original id': 12345,
    error: 0,
    other: '',
    testB: 'test.example.\t0\tANY\tTSIG\tHMAC-SHA256.\t853804800\t300\t8\tdeadbeef\t12345\t0\t0\n',
    testT:
      ':test.example:250:\\013HMAC-SHA256\\000\\062\\344\\007\\000\\001\\054\\000\\004\\336\\255\\276\\357\\060\\071\\000\\000:0::\n',
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
  base.getFields(TSIG, ['algorithm name', 'time signed', 'fudge', 'mac', 'original id', 'error', 'other'])
  base.getCanonical(TSIG)
  base.getTypeId(TSIG, 250)
  base.getTags(TSIG)

  base.toBind(TSIG, validRecords)
  base.toWire(TSIG, validRecords)
  base.toTinydns(TSIG, validRecords)

  base.fromBind(TSIG, validRecords)
  base.fromTinydns(TSIG, validRecords)
})
