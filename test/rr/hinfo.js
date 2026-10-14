import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from '../base.js'

import HINFO from '../../rr/hinfo.js'

const defaults = { ttl: 86400 }

const valid = [
  {
    ...defaults,
    owner: 'server-under-my-desk.example.com.',
    cpu: 'PDP-11/73',
    os: 'UNIX',
    testB: 'server-under-my-desk.example.com.\t86400\tIN\tHINFO\t"PDP-11/73"\t"UNIX"\n',
    testT: ':server-under-my-desk.example.com:13:\\011PDP-11/73\\004UNIX:86400::\n',
  },
  {
    ...defaults,
    owner: 'sri-nic.arpa.',
    cpu: 'DEC-2060',
    os: 'TOPS20',
    testB: 'sri-nic.arpa.\t86400\tIN\tHINFO\t"DEC-2060"\t"TOPS20"\n',
    testT: ':sri-nic.arpa:13:\\010DEC-2060\\006TOPS20:86400::\n',
  },
  {
    owner: 'hinfo.nictool.tnpi.net.',
    cpu: 'Intel-Xeon',
    os: 'Linux',
    testB: 'hinfo.nictool.tnpi.net.\t3600\tIN\tHINFO\t"Intel-Xeon"\t"Linux"\n',
    testT: ':hinfo.nictool.tnpi.net:13:\\012Intel-Xeon\\005Linux:3600::\n',
    testW:
      '0568696e666f076e6963746f6f6c04746e7069036e657400000d000100000e1000110a496e74656c2d58656f6e054c696e7578',
  },
]

const invalid = [
  {
    ...defaults,
    owner: 'www.example.com.',
    address: '',
    msg: /HINFO: cpu is required/,
  },
  ...['cpu', 'os'].flatMap((f) =>
    ['a'.repeat(256), 'é'.repeat(128)].map((v) => ({
      owner: 'h.example.',
      cpu: 'x',
      os: 'x',
      [f]: v,
      msg: /must be <=255 bytes/,
    })),
  ),
]

describe('HINFO record', function () {
  base.suite(HINFO, { typeId: 13, fields: ['cpu', 'os'], valid, invalid })

  it('counts UTF-8 bytes against the 255 limit', function () {
    assert.equal(
      new HINFO({ owner: 'h.example.', ttl: 60, cpu: 'é'.repeat(127), os: 'x' }).get('cpu'),
      'é'.repeat(127),
    )
  })

  it('exports MaraDNS csv2 as two ;-separated chunks, payload quotes intact', function () {
    const r = new HINFO({ owner: 'h.example.', ttl: 60, cpu: '"x"', os: "it's" })
    assert.equal(r.toMaraDNS(), `h.example.\t+60\tHINFO\t'"x"';'it'\\x27's' ~\n`)
  })
})
