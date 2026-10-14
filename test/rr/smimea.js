import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import SMIMEA from '../../rr/smimea.js'

const valid = [
  {
    owner: '_443._tcp.www.example.com.',
    'certificate usage': 0,
    selector: 0,
    'matching type': 1,
    'certificate association data': 'D2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971',
    testB:
      '_443._tcp.www.example.com.\t3600\tIN\tSMIMEA\t0\t0\t1\tD2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971\n',
    testT:
      ':_443._tcp.www.example.com:53:\\000\\000\\001\\322\\253\\336$\\015|\\323\\356kK(\\305M\\3604\\271y\\203\\241\\321n\\212A\\016Ea\\313\\020f\\030\\351q:3600::\n',
    testW:
      '045f343433045f74637003777777076578616d706c6503636f6d000035000100000e100023000001d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971',
  },
]

const invalid = [
  {
    owner: 'test.example.com.',
    'certificate usage': 0,
    selector: 6, // invalid
    'matching type': 1,
    'certificate association data': '( D2ABDE240D7CD3EE6B4B28C54DF034B9 7983A1D16E8A410E4561CB106618E971 )',
    msg: /selector invalid/,
  },
]

describe('SMIMEA record', function () {
  base.suite(SMIMEA, {
    typeId: 53,
    fields: ['certificate usage', 'selector', 'matching type', 'certificate association data'],
    valid,
    invalid,
  })

  it('revalidates the certificate association data when the matching type changes', function () {
    const r = new SMIMEA(new SMIMEA(null).getCanonical())
    assert.throws(() => r.setMatchingType(2), /certificate association data must be 64 bytes/)
    assert.equal(r.get('matching type'), 1)
  })
})
