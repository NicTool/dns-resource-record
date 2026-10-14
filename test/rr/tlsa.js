import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import TLSA from '../../rr/tlsa.js'

const defaults = { class: 'IN', ttl: 3600, type: 'TLSA' }

const validRecords = [
  {
    ...defaults,
    owner: '_443._tcp.www.example.com.',
    'certificate usage': 0,
    selector: 0,
    'matching type': 1,
    'certificate association data': 'D2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971',
    testB:
      '_443._tcp.www.example.com.\t3600\tIN\tTLSA\t0\t0\t1\tD2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971\n',
    testT:
      ':_443._tcp.www.example.com:52:\\000\\000\\001\\322\\253\\336$\\015|\\323\\356kK(\\305M\\3604\\271y\\203\\241\\321n\\212A\\016Ea\\313\\020f\\030\\351q:3600::\n',
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
      '92003BA34942DC74152E2F2C408D29ECA5A520E7F2E06BB944F4DCA346BAF63C1B177615D466F6C4B71C216A50292BD58C9EBDD2F74E38FE51FFD48C43326CBC',
    testB: `_443._tcp.www.example.com.\t3600\tIN\tTLSA\t1\t1\t2\t92003BA34942DC74152E2F2C408D29ECA5A520E7F2E06BB944F4DCA346BAF63C1B177615D466F6C4B71C216A50292BD58C9EBDD2F74E38FE51FFD48C43326CBC\n`,
    testT:
      ':_443._tcp.www.example.com:52:\\001\\001\\002\\222\\000;\\243IB\\334t\\025./,@\\215)\\354\\245\\245 \\347\\362\\340k\\271D\\364\\334\\243F\\272\\366<\\033\\027v\\025\\324f\\366\\304\\267\\034!jP)+\\325\\214\\236\\275\\322\\367N8\\376Q\\377\\324\\214C2l\\274:3600::\n',
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
  base.fromWire(TLSA, validRecords)

  it('revalidates the certificate association data when the matching type changes', function () {
    const r = new TLSA(new TLSA(null).getCanonical())
    assert.throws(() => r.setMatchingType(2), /certificate association data must be 64 bytes/)
    assert.equal(r.get('matching type'), 1)
  })
})
