
const assert = require('assert')

exports.valid = (type, validRecords) => {

  for (const val of validRecords) {
    // console.log(val)
    it(`parses valid ${val.type} record (${val.name})`, async function () {
      const r = new type(val)
      if (process.env.DEBUG) console.dir(r)

      for (const k of Object.keys(val)) {
        if (/^test/.test(k)) continue
        assert.strictEqual(r.get(k), val[k], `${k} ${r.get(k)} !== ${val[k]}`)
      }
    })
  }
}

exports.invalid = (type, invalidRecords) => {

  for (const inv of invalidRecords) {
    it(`throws on invalid ${type.name} record (${inv.name})`, async function () {
      try {
        new type(inv)
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

exports.toBind = (type, validRecords) => {

  for (const val of validRecords) {
    it(`exports ${val.type} to BIND (${val.name})`, async function () {
      const r = new type(val).toBind()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testR)
    })
  }
}

exports.toTinydns = (type, validRecords) => {

  for (const val of validRecords) {
    it(`exports ${val.type} to tinydns (${val.name})`, async function () {
      const r = new type(val).toTinydns()
      if (process.env.DEBUG) console.dir(r)
      assert.strictEqual(r, val.testT)
    })
  }
}

exports.getRFCs = (type, valid) => {
  it(`can retrieve RFCs for ${valid.type}`, async function () {
    const r = new type(valid)
    assert.ok(r.getRFCs().length)
  })
}
