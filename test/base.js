
const assert = require('assert')

const ResourceRecord = require('../index.js')

exports.valid = validRecords => {

  for (const val of validRecords) {
    // console.log(val)
    it(`parses valid ${val.type} record`, async function () {
      const r = new ResourceRecord[val.type](val)
      if (process.env.DEBUG) console.dir(r)

      for (const k of Object.keys(val)) {
        assert.strictEqual(r.get(k), val[k], `${k} ${r.get(k)} !== ${val[k]}`)
      }
    })
  }
}

exports.invalid = invalidRecords => {
  for (const inv of invalidRecords) {

    const ucType = inv.type.toUpperCase()

    it(`throws on invalid ${ucType} record`, async function () {
      try {
        new ResourceRecord[ucType](inv)
      }
      catch (e) {
        if (process.env.DEBUG) console.error(e.message)
        assert.ok(e)
        return
      }
      throw new Error(`failed to throw`)
    })
  }
}

