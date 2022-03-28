
const assert = require('assert')

exports.valid = (type, validRecords, defaults) => {
  describe('valid', function () {
    for (const val of validRecords) {
      // console.log(val)
      it(`parses record: ${val.owner}`, async function () {
        if (defaults) val.default = defaults
        const r = new type(val)
        if (defaults) delete val.default
        if (process.env.DEBUG) console.dir(r)

        for (const k of Object.keys(val)) {
          if (/^test/.test(k)) continue
          assert.strictEqual(r.get(k), val[k], `${k} ${r.get(k)} !== ${val[k]}`)
        }
      })
    }
  })
}

exports.invalid = (type, invalidRecords, defaults) => {
  describe('invalid', function () {
    for (const inv of invalidRecords) {
      if (defaults) inv.default = defaults
      it(`throws on record (${inv.owner})`, async function () {
        try {
          assert.deepEqual(new type(inv), null)
        }
        catch (e) {
          if (process.env.DEBUG) console.error(e.message)
          assert.ok(e)
          return
        }
        throw new Error(`failed to throw`)
      })
    }
  })
}

exports.toBind = (type, validRecords) => {
  describe('toBind', function () {
    for (const val of validRecords) {
      it(`exports to BIND: ${val.owner}`, async function () {
        const r = new type(val).toBind()
        if (process.env.DEBUG) console.dir(r)
        assert.strictEqual(r, val.testB)
      })
    }
  })
}

exports.toTinydns = (type, validRecords) => {
  describe('toTinydns', function () {
    for (const val of validRecords) {
      it(`exports to tinydns: ${val.owner}`, async function () {
        const r = new type(val).toTinydns()
        if (process.env.DEBUG) console.dir(r)
        assert.strictEqual(r, val.testT)
      })
    }
  })
}

exports.getDescription = type => {
  describe('getDescription', function () {
    const desc = new type(null).getDescription()
    it(`gets description: ${desc}`, async function () {
      assert.ok(desc)
    })
  })
}

exports.getRFCs = (type, valid) => {
  describe('getRFCs', function () {
    it(`can retrieve RFCs`, async function () {
      const r = new type(null)
      assert.ok(r.getRFCs().length)
    })
  })
}

function checkFromNS (type, validRecords, nsName, nsLineName) {
  for (const val of validRecords) {
    it(`imports ${nsName} record: ${val.owner}`, async function () {
      const r = new type({ [nsLineName]: nsLineName === 'bindline' ? val.testB : val.testT })
      if (process.env.DEBUG) console.dir(r)
      for (const f of r.getFields()) {
        if (f === 'class') continue
        let expected = val[f]
        if (f === 'data' && Array.isArray(expected)) expected = expected.join('') // TXT
        assert.deepStrictEqual(r.get(f), expected, `${f}: ${r.get(f)} !== ${expected}`)
      }
    })
  }
}

exports.fromTinydns = (type, validRecords) => {
  describe('fromTinydns', function () {
    checkFromNS(type, validRecords, 'tinydns', 'tinyline')
  })
}

exports.fromBind = (type, validRecords) => {
  describe('fromBind', function () {
    checkFromNS(type, validRecords, 'BIND', 'bindline')
  })
}

exports.getFields = (type, rdataFields) => {
  describe('getFields', function () {
    it(`can retrieve record fields`, async function () {
      const r = new type(null)
      // console.log(new type(null).getFields('rdata'))
      assert.deepEqual(r.getFields('rdata'), rdataFields)
      assert.deepEqual(r.getFields(), r.getFields('common').concat(rdataFields))
    })
  })
}

exports.getTypeId = (type, val) => {
  describe('getTypeId', function () {
    it(`can retrieve record type ID`, async function () {
      const r = new type(null)
      assert.deepEqual(r.getTypeId(), val)
    })
  })
}