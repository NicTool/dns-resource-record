import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

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
    testB: 'test.example.\t0\tANY\tTSIG\tSAMPLE-ALG.EXAMPLE.\t853804800\t300\t0\t0\t0\t0\n',
    testT:
      ':test.example:250:\\012SAMPLE-ALG\\007EXAMPLE\\000\\000\\000\\062\\344\\007\\000\\001\\054\\000\\000\\000\\000\\000\\000\\000\\000:0::\n',
    testW:
      '0474657374076578616d706c650000fa00ff0000000000240a53414d504c452d414c47074558414d504c4500000032e40700012c0000000000000000',
  },
  {
    ...defaults,
    owner: 'test.example.',
    'algorithm name': 'HMAC-SHA256.',
    'time signed': 853804800,
    fudge: 300,
    mac: '3q2+7w==',
    'original id': 12345,
    error: 0,
    other: '',
    testB: 'test.example.\t0\tANY\tTSIG\tHMAC-SHA256.\t853804800\t300\t4\t3q2+7w==\t12345\t0\t0\n',
    testT:
      ':test.example:250:\\013HMAC-SHA256\\000\\000\\000\\062\\344\\007\\000\\001\\054\\000\\004\\336\\255\\276\\357\\060\\071\\000\\000\\000\\000:0::\n',
    testW:
      '0474657374076578616d706c650000fa00ff0000000000210b484d41432d53484132353600000032e40700012c0004deadbeef303900000000',
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

  base.fromBind(TSIG, validRecords)
  base.fromTinydns(TSIG, validRecords)
  base.fromWire(TSIG, validRecords)

  it('imports dig output: error mnemonic and Other Data', function () {
    const r = TSIG.fromBind(
      'test.example. 0 ANY TSIG hmac-sha256. 1099511627781 300 4 3q2+ 7w== 1 BADTIME 6 AAAAAAAA',
    )
    assert.equal(r.get('time signed'), 2 ** 40 + 5)
    assert.equal(r.get('mac'), '3q2+7w==')
    assert.equal(r.get('error'), 18)
    assert.equal(r.get('other'), 'AAAAAAAA')
    assert.ok(
      Buffer.from(r.toWire())
        .toString('hex')
        .endsWith('010000000005' + '012c' + '0004deadbeef' + '0001' + '0012' + '0006000000000000'),
    )
  })

  it('rejects an error that is neither an rcode name nor an integer', function () {
    assert.throws(
      () => TSIG.fromBind('t.example. 0 ANY TSIG hmac-sha256. 1 300 0 1 18junk 0'),
      /TSIG: error must be an rcode name or an integer: 18junk/,
    )
  })

  it('rejects wire rdata whose lengths do not account for every byte', function () {
    const tsig = new TSIG({ ...validRecords[1], other: 'AA==' })
    const rdata = tsig.getWireRdata()
    const decode = (bytes) =>
      new TSIG(null).fromWire({ owner: 'test.example.', cls: 'ANY', ttl: 0, rdata: bytes })
    assert.equal(decode(rdata).get('other'), 'AA==')
    assert.throws(() => decode(Uint8Array.from([...rdata, 0xff])), /1 bytes after Other Data/)
    assert.throws(() => decode(rdata.subarray(0, rdata.length - 1)), /rdata is truncated/)
  })

  it('joins base64 split before its padding', function () {
    assert.equal(TSIG.fromBind('t.example. 0 ANY TSIG hmac-sha256. 1 300 2 AAA = 1 0 0').get('mac'), 'AAA=')
  })

  it('rejects a MAC shorter than its size', function () {
    assert.throws(
      () => TSIG.fromBind('test.example. 0 ANY TSIG hmac-sha256. 1 300 8 3q2+7w== 1 0 0'),
      /TSIG: missing rdata: mac/,
    )
  })

  describe('zone-data exports reject TSIG', function () {
    // RFC 8945 §§4.1-4.2: TSIG is a dynamically computed meta-RR of class ANY
    // with no value in storage; tinydns and MaraDNS formats publish class IN
    it('toTinydns throws', function () {
      assert.throws(() => new TSIG(validRecords[0]).toTinydns(), /only class IN/)
    })

    it('toMaraDNS throws', function () {
      assert.throws(() => new TSIG(validRecords[0]).toMaraDNS(), /only class IN/)
    })
  })
})
