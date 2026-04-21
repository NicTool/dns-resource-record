import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import * as base from './base.js'

import LOC from '../rr/loc.js'

const defaults = { class: 'IN', ttl: 3600, type: 'LOC' }

const validRecords = [
  {
    ...defaults,
    owner: 'loc.home.example.com.',
    address: '47 43 47 N 122 21 35 W 132m 100m 100m 2m',
    testB: `loc.home.example.com.\t3600\tIN\tLOC\t47 43 47 N 122 21 35 W 132m 100m 100m 2m\n`,
    testT:
      ':loc.home.example.com:29:\\000\\024\\024\\042\\212\\075\\337\\070\\145\\276\\224\\150\\000\\230\\312\\020:3600::\n',
  },
  {
    ...defaults,
    owner: 'cambridge-net.kei.com.',
    address: '42 21 54 N 71 6 18 W -24m 30m',
    testB: 'cambridge-net.kei.com.\t3600\tIN\tLOC\t42 21 54 N 71 6 18 W -24m 30m\n',
    testT:
      ':cambridge-net.kei.com:29:\\000\\063\\000\\000\\211\\027\\055\\320\\160\\276\\025\\360\\000\\230\\215\\040:3600::\n',
  },
  {
    ...defaults,
    owner: 'rwy04l.logan-airport.boston.',
    address: '42 21 28.764 N 71 0 51.617 W -44m 2000m',
    testB: 'rwy04l.logan-airport.boston.\t3600\tIN\tLOC\t42 21 28.764 N 71 0 51.617 W -44m 2000m\n',
    testT:
      ':rwy04l.logan-airport.boston:29:\\000\\045\\000\\000\\211\\026\\313\\074\\160\\303\\020\\337\\000\\230\\205\\120:3600::\n',
  },
  {
    owner: 'loc.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'LOC',
    address: '37 46 39 N 122 25 9 W 16m 1m 10000m 10m',
    testB: 'loc.nictool.tnpi.net.\t3600\tIN\tLOC\t37 46 39 N 122 25 9 W 16m 1m 10000m 10m\n',
    testT: ':loc.nictool.tnpi.net:29:\\000\\022\\026\\023\\210\\033\\056\\030\\145\\273\\120\\170\\000\\230\\234\\300:3600::\n',
    testW: '036c6f63076e6963746f6f6c04746e7069036e657400001d000100000e10001000121613881b2e1865bb507800989cc0',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'server.example.com.',
    address: '', // empty
    msg: /address is required/,
  },
]

describe('LOC record', function () {
  base.valid(LOC, validRecords)
  base.invalid(LOC, invalidRecords)

  base.getDescription(LOC)
  base.getRFCs(LOC, validRecords[0])
  base.getFields(LOC, ['address'])
  base.getCanonical(LOC)
  base.getTypeId(LOC, 29)
  base.getTags(LOC)

  base.toBind(LOC, validRecords)
  base.toWire(LOC, validRecords)
  base.toTinydns(LOC, validRecords)

  describe('toExponent', function () {
    const loc = new LOC(validRecords[0])
    it('converts a SIZE/PREC to exponent format', function () {
      assert.equal(loc.toExponent(100), 18)
    })
  })

  describe('fromExponent', function () {
    const loc = new LOC(validRecords[0])
    it('decodes an exponent format to SIZE/PREC', function () {
      assert.equal(loc.fromExponent(18), 100)
    })
  })

  base.fromTinydns(LOC, validRecords)
  base.fromBind(LOC, validRecords)
})
