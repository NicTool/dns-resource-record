import { describe } from 'node:test'
import * as base from './base.js'

import TLSA from '../rr/tlsa.js'

const defaults = { class: 'IN', ttl: 3600, type: 'TLSA' }

const validRecords = [
  {
    ...defaults,
    owner: '_443._tcp.www.example.com.',
    'certificate usage': 0,
    selector: 0,
    'matching type': 1,
    'certificate association data': 'd2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971',
    testB:
      '_443._tcp.www.example.com.\t3600\tIN\tTLSA\t0\t0\t1\td2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971\n',
    testT:
      ':_443._tcp.www.example.com:52:\\000\\000\\001\\322\\253\\336\\044\\015\\174\\323\\356\\153\\113\\050\\305\\115\\360\\064\\271\\171\\203\\241\\321\\156\\212\\101\\016\\105\\141\\313\\020\\146\\030\\351\\161:3600::\n',
    testW:
      '045f343433045f74637003777777076578616d706c6503636f6d000034000100000e100023000001d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971',
  },
  {
    ...defaults,
    owner: '_443._tcp.www.example.com.',
    'certificate usage': 1,
    selector: 1,
    'matching type': 2,
    'certificate association data':
      '92003ba34942dc74152e2f2c408d29eca5a520e7f2e06bb944f4dca346baf63c1b177615d466f6c4b71c216a50292bd58c9ebdd2f74e38fe51ffd48c43326cbc',
    testB: `_443._tcp.www.example.com.\t3600\tIN\tTLSA\t1\t1\t2\t92003ba34942dc74152e2f2c408d29eca5a520e7f2e06bb944f4dca346baf63c1b177615d466f6c4b71c216a50292bd58c9ebdd2f74e38fe51ffd48c43326cbc\n`,
    testT:
      ':_443._tcp.www.example.com:52:\\001\\001\\002\\222\\000\\073\\243\\111\\102\\334\\164\\025\\056\\057\\054\\100\\215\\051\\354\\245\\245\\040\\347\\362\\340\\153\\271\\104\\364\\334\\243\\106\\272\\366\\074\\033\\027\\166\\025\\324\\146\\366\\304\\267\\034\\041\\152\\120\\051\\053\\325\\214\\236\\275\\322\\367\\116\\070\\376\\121\\377\\324\\214\\103\\062\\154\\274:3600::\n',
    testW:
      '045f343433045f74637003777777076578616d706c6503636f6d000034000100000e10004301010292003ba34942dc74152e2f2c408d29eca5a520e7f2e06bb944f4dca346baf63c1b177615d466f6c4b71c216a50292bd58c9ebdd2f74e38fe51ffd48c43326cbc',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    selector: 6, // invalid
    msg: /RFC/,
  },
]

describe('TLSA record', function () {
  base.valid(TLSA, validRecords)
  base.invalid(TLSA, invalidRecords)

  base.getDescription(TLSA)
  base.getRFCs(TLSA, validRecords[0])
  base.getFields(TLSA, ['certificate usage', 'selector', 'matching type', 'certificate association data'])
  base.getCanonical(TLSA)
  base.getTypeId(TLSA, 52)
  base.getTags(TLSA)

  base.toBind(TLSA, validRecords)
  base.toWire(TLSA, validRecords)
  base.toTinydns(TLSA, validRecords)

  base.fromBind(TLSA, validRecords)
  base.fromTinydns(TLSA, validRecords)
})
