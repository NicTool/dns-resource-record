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
    'certificate association data': 'd2abde240d7cd3ee6b4b28c54df034b9 7983a1d16e8a410e4561cb106618e971',
    testB:
      '_443._tcp.www.example.com.\t3600\tIN\tTLSA\t0\t0\t1\td2abde240d7cd3ee6b4b28c54df034b9 7983a1d16e8a410e4561cb106618e971\n',
    testT:
      ':_443._tcp.www.example.com:52:\\000\\000\\001d2abde240d7cd3ee6b4b28c54df034b9 7983a1d16e8a410e4561cb106618e971:3600::\n',
  },
  {
    ...defaults,
    owner: '_443._tcp.www.example.com.',
    'certificate usage': 1,
    selector: 1,
    'matching type': 2,
    'certificate association data':
      '92003ba34942dc74152e2f2c408d29ec a5a520e7f2e06bb944f4dca346baf63c 1b177615d466f6c4b71c216a50292bd5 8c9ebdd2f74e38fe51ffd48c43326cbc',
    testB: `_443._tcp.www.example.com.\t3600\tIN\tTLSA\t1\t1\t2\t92003ba34942dc74152e2f2c408d29ec a5a520e7f2e06bb944f4dca346baf63c 1b177615d466f6c4b71c216a50292bd5 8c9ebdd2f74e38fe51ffd48c43326cbc\n`,
    testT:
      ':_443._tcp.www.example.com:52:\\001\\001\\00292003ba34942dc74152e2f2c408d29ec a5a520e7f2e06bb944f4dca346baf63c 1b177615d466f6c4b71c216a50292bd5 8c9ebdd2f74e38fe51ffd48c43326cbc:3600::\n',
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
  base.getTypeId(TLSA, 52)

  base.toBind(TLSA, validRecords)
  base.toTinydns(TLSA, validRecords)

  base.fromBind(TLSA, validRecords)
  base.fromTinydns(TLSA, validRecords)
})
