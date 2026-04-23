import { describe } from 'node:test'
import * as base from '../base.js'

import SMIMEA from '../../rr/smimea.js'

const defaults = { class: 'IN', ttl: 3600, type: 'SMIMEA' }

const validRecords = [
  {
    ...defaults,
    owner: '_443._tcp.www.example.com.',
    'certificate usage': 0,
    selector: 0,
    'matching type': 1,
    'certificate association data': 'd2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971',
    testB:
      '_443._tcp.www.example.com.\t3600\tIN\tSMIMEA\t0\t0\t1\td2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971\n',
    testT:
      ':_443._tcp.www.example.com:53:\\000\\000\\001\\322\\253\\336\\044\\015\\174\\323\\356\\153\\113\\050\\305\\115\\360\\064\\271\\171\\203\\241\\321\\156\\212\\101\\016\\105\\141\\313\\020\\146\\030\\351\\161:3600::\n',
    testW:
      '045f343433045f74637003777777076578616d706c6503636f6d000035000100000e100023000001d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    'certificate usage': 0,
    selector: 6, // invalid
    'matching type': 1,
    'certificate association data': '( d2abde240d7cd3ee6b4b28c54df034b9 7983a1d16e8a410e4561cb106618e971 )',
    msg: /selector invalid/,
  },
]

describe('SMIMEA record', function () {
  base.valid(SMIMEA, validRecords)
  base.invalid(SMIMEA, invalidRecords)

  base.getDescription(SMIMEA)
  base.getRFCs(SMIMEA, validRecords[0])
  base.getFields(SMIMEA, ['certificate usage', 'selector', 'matching type', 'certificate association data'])
  base.getCanonical(SMIMEA)
  base.getTypeId(SMIMEA, 53)
  base.getTags(SMIMEA)

  base.toBind(SMIMEA, validRecords)
  base.toWire(SMIMEA, validRecords)
  base.toTinydns(SMIMEA, validRecords)

  base.fromBind(SMIMEA, validRecords)
  base.fromTinydns(SMIMEA, validRecords)
})
