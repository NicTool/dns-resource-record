
const assert = require('assert')

const base = require('./base')

const LOC = require('../rr/loc')

const validRecords = [
  {
    class  : 'IN',
    name   : 'loc.home.example.com',
    type   : 'LOC',
    address: '47 43 47 N 122 21 35 W 132 100m 100m 2m',
    ttl    : 3600,
    testR  : `loc.home.example.com\t3600\tIN\tLOC\t47 43 47 N 122 21 35 W 132 100m 100m 2m\n`,
    testT  : ':loc.home.example.com:29:\\000\\024\\024\\042\\212\\075\\337\\070\\145\\276\\224\\150\\000\\230\\312\\020:3600::\n',
  },
  {
    name   : 'cambridge-net.kei.com',
    type   : 'LOC',
    address: '42 21 54 N 71 06 18 W -24m 30m',
    ttl    : 3600,
    testR  : 'cambridge-net.kei.com\t3600\tIN\tLOC\t42 21 54 N 71 06 18 W -24m 30m\n',
    testT  : ':cambridge-net.kei.com:29:\\000\\063\\000\\000\\211\\027\\055\\320\\160\\276\\025\\360\\000\\230\\215\\040:3600::\n',
  },
  {
    name   : 'rwy04L.logan-airport.boston',
    type   : 'LOC',
    address: '42 21 28.764 N 71 00 51.617 W -44m 2000m',
    ttl    : 3600,
    testR  : 'rwy04L.logan-airport.boston\t3600\tIN\tLOC\t42 21 28.764 N 71 00 51.617 W -44m 2000m\n',
    testT  : ':rwy04L.logan-airport.boston:29:\\000\\045\\000\\000\\211\\026\\313\\074\\160\\303\\020\\337\\000\\230\\205\\120:3600::\n',
  },
  {
    name   : 'loc.home.simerson.net',
    type   : 'LOC',
    address: '47 43 47.000 N 122 21 35.000 W 132.00m 100m 100m 2m',
    ttl    : 86400,
    testR  : 'loc.home.simerson.net\t86400\tIN\tLOC\t47 43 47.000 N 122 21 35.000 W 132.00m 100m 100m 2m\n',
    testT  : ':loc.home.simerson.net:29:\\000\\024\\024\\042\\212\\075\\337\\070\\145\\276\\224\\150\\000\\230\\312\\020:86400::\n',
  },
]

const invalidRecords = [
  {
    class  : 'IN',
    name   : 'server.example.com',
    type   : 'LOC',
    address: '', // empty
    ttl    : 3600,
  },
]

describe('LOC record', function () {
  base.valid(LOC, validRecords)
  base.invalid(LOC, invalidRecords)

  for (const val of validRecords) {
    it(`converts to BIND format (${val.name})`, async function () {
      const r = new LOC(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })

    it(`converts to tinydns format (${val.name})`, async function () {
      const r = new LOC(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testT)
    })
  }
})
