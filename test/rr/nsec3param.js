import { describe } from 'node:test'
import * as base from '../base.js'

import NSEC3PARAM from '../../rr/nsec3param.js'

const valid = [
  {
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

const invalid = [
  ['hash algorithm', undefined, /hash algorithm/i],
  ['flags', 256, /flags/i],
  ['iterations', -1, /iterations/i],
  ['salt', 'XYZ', /must be hex octets or/i],
  ['salt', 'abc', /must be hex octets/],
  ['salt', undefined, /'salt' is required/],
]
  .map(([f, v, msg]) => ({ ...valid[0], [f]: v, msg }))
  .concat({ tinyline: ':example.com:51:AB:3600::\n', msg: /salt length does not match/ })

describe('NSEC3PARAM record', function () {
  base.suite(NSEC3PARAM, {
    typeId: 51,
    fields: ['hash algorithm', 'flags', 'iterations', 'salt'],
    valid,
    invalid,
  })
})
