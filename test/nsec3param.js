import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from './base.js'

import NSEC3PARAM from '../rr/nsec3param.js'

const defaults = { class: 'IN', ttl: 3600, type: 'NSEC3PARAM' }

const validRecords = [
  {
    ...defaults,
    owner: 'test.example.com.',
    'hash algorithm': 1,
    flags: 1,
    iterations: 12,
    salt: 'aabbccdd',
    testB: 'test.example.com.\t3600\tIN\tNSEC3PARAM\t1\t1\t12\taabbccdd\n',
    testT: ':test.example.com:51:\\001\\001\\000\\014\\004\\252\\273\\314\\335:3600::\n',
    testW: '0474657374076578616d706c6503636f6d000033000100000e1000090101000c04aabbccdd',
  },
  {
    ...defaults,
    owner: 'example.com.',
    'hash algorithm': 1,
    flags: 0,
    iterations: 0,
    salt: '-',
    testB: 'example.com.\t3600\tIN\tNSEC3PARAM\t1\t0\t0\t-\n',
    testT: ':example.com:51:\\001\\000\\000\\000\\000:3600::\n',
    testW: '076578616d706c6503636f6d000033000100000e1000050100000000',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'bad.example.',
    // missing hash algorithm
    flags: 0,
    iterations: 0,
    salt: '-',
    msg: /hash algorithm/i,
  },
  {
    ...defaults,
    owner: 'bad2.example.',
    'hash algorithm': 1,
    // invalid flags (out of 8-bit range)
    flags: 256,
    iterations: 0,
    salt: '-',
    msg: /flags/i,
  },
  {
    ...defaults,
    owner: 'bad3.example.',
    'hash algorithm': 1,
    flags: 0,
    // invalid iterations (negative)
    iterations: -1,
    salt: '-',
    msg: /iterations/i,
  },
  {
    ...defaults,
    owner: 'bad4.example.',
    'hash algorithm': 1,
    flags: 0,
    iterations: 0,
    salt: 'XYZ', // not valid hex or dash
    msg: /must be hex or/i,
  },
]

describe('NSEC3PARAM record', function () {
  base.valid(NSEC3PARAM, validRecords)
  base.invalid(NSEC3PARAM, invalidRecords, { ttl: 3600 })

  base.getDescription(NSEC3PARAM)
  base.getRFCs(NSEC3PARAM, validRecords[0])
  base.getFields(NSEC3PARAM, ['hash algorithm', 'flags', 'iterations', 'salt'])
  base.getCanonical(NSEC3PARAM)
  base.getTypeId(NSEC3PARAM, 51)
  base.getTags(NSEC3PARAM)

  base.toBind(NSEC3PARAM, validRecords)
  base.toWire(NSEC3PARAM, validRecords)
  base.toTinydns(NSEC3PARAM, validRecords)

  base.fromBind(NSEC3PARAM, validRecords)
  base.fromTinydns(NSEC3PARAM, validRecords)

  it('throws when fromTinydns RDATA is too short', function () {
    assert.throws(() => NSEC3PARAM.fromTinydns(':example.com:51:AB:3600::\n'), /RDATA too short/)
  })
})
