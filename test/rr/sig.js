import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import SIG from '../../rr/sig.js'

const defaults = { class: 'IN', ttl: 3600, type: 'SIG' }

const validRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    'type covered': 1,
    algorithm: 5,
    labels: 1,
    'original ttl': 3600,
    'signature expiration': 1678886400,
    'signature inception': 1678886400,
    'key tag': 12345,
    'signers name': 'example.com.',
    signature:
      'AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==',
    testB:
      'example.com.\t3600\tIN\tSIG\t1\t5\t1\t3600\t20230315132000\t20230315132000\t12345\texample.com.\tAQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==\n',
    testT:
      ':example.com:24:\\000\\001\\005\\001\\000\\000\\016\\020\\144\\021\\306\\000\\144\\021\\306\\000\\060\\071\\007example\\003com\\000\\001\\003\\322\\052l\\247\\1775\\270\\223\\040o\\323\\136LPm\\203x\\2047\\011\\271\\176\\004\\026G\\341\\277\\364\\075\\215d\\306I\\257\\0367\\031s\\311\\350\\221\\374\\343\\337Q\\232\\214\\204\\012c\\356B\\246\\322\\353\\335\\273\\227\\003\\135\\041Z\\244\\344\\027\\261\\372E\\372\\021\\251t\\036\\242\\011\\214\\035\\372\\137\\265\\376\\2632\\375K\\310\\025\\040\\211\\256\\363k\\246D\\314\\342A\\073\\073r\\276\\030\\313\\357\\215\\242S\\364\\351\\075\\041\\003\\206m\\2224\\242\\342\\215\\365\\051\\246\\175Th\\333\\357\\343:3600::\n',
    testW:
      '076578616d706c6503636f6d000018000100000e1000a10001050100000e106411c6006411c6003039076578616d706c6503636f6d000103d22a6ca77f35b893206fd35e4c506d8378843709b97e041647e1bff43d8d64c649af1e371973c9e891fce3df519a8c840a63ee42a6d2ebddbb97035d215aa4e417b1fa45fa11a9741ea2098c1dfa5fb5feb332fd4bc8152089aef36ba644cce2413b3b72be18cbef8da253f4e93d2103866d9234a2e28df529a67d5468dbefe3',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    algorithm: 5,
    labels: 1,
    'original ttl': 3600,
    'signature expiration': 1678886400,
    'signature inception': 1678886400,
    'key tag': 12345,
    'signers name': 'example.com.',
    signature: 'AQPSK==',
    msg: /'type covered' is required/i,
  },
]

describe('SIG record', function () {
  base.valid(SIG, validRecords)
  base.invalid(SIG, invalidRecords)

  base.getDescription(SIG)
  base.getRFCs(SIG, validRecords[0])
  base.getFields(SIG, [
    'type covered',
    'algorithm',
    'labels',
    'original ttl',
    'signature expiration',
    'signature inception',
    'key tag',
    'signers name',
    'signature',
  ])
  base.getCanonical(SIG)
  base.getTypeId(SIG, 24)
  base.getTags(SIG)

  base.toBind(SIG, validRecords)
  base.toWire(SIG, validRecords)
  base.toTinydns(SIG, validRecords)

  base.fromBind(SIG, validRecords)
  base.fromTinydns(SIG, validRecords)
  base.fromWire(SIG, validRecords)

  it('imports BIND output: type mnemonic, dates, and split base64', function () {
    const r = SIG.fromBind(
      'example.com. 3600 IN SIG A 5 1 3600 20230315132000 20230315132000 12345 example.com. AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w==',
    )
    assert.equal(r.get('type covered'), 1)
    assert.equal(r.get('signature expiration'), 1678886400)
    assert.equal(r.get('signature'), validRecords[0].signature)
  })

  it('rejects a date that does not exist', function () {
    assert.throws(
      () => new SIG({ ...validRecords[0], 'signature expiration': 20230231000000 }),
      /signature expiration is not a valid date/,
    )
  })
})
