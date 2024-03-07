import assert from 'assert'

export function valid(type, validRecords, defaults) {
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
          assert.strictEqual(
            r.get(k),
            val[k],
            `${type.name} ${k} ${r.get(k)} !== ${val[k]}`,
          )
        }
      })
    }
  })
}

export function invalid(type, invalidRecords, defaults) {
  describe('invalid', function () {
    for (const inv of invalidRecords) {
      if (defaults) inv.default = defaults
      it(`throws on record (${inv.owner})`, async function () {
        assert.throws(
          () => {
            new type(inv)
          },
          {
            message: inv.msg,
          },
        )
      })
    }
  })
}

export function toBind(type, validRecords) {
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

export function toTinydns(type, validRecords) {
  describe('toTinydns', function () {
    for (const val of validRecords) {
      if (val.testT === undefined) continue
      it(`exports to tinydns: ${val.owner}`, async function () {
        const r = new type(val).toTinydns()
        if (process.env.DEBUG) console.dir(r)
        assert.strictEqual(r, val.testT)
      })
    }
  })
}

export function getDescription(type) {
  describe('getDescription', function () {
    const desc = new type(null).getDescription()
    it(`gets description: ${desc}`, async function () {
      assert.ok(desc)
    })
  })
}

export function getRFCs(type, valid) {
  describe('getRFCs', function () {
    const r = new type(null)
    const rfcs = r.getRFCs()
    it(`can retrieve RFCs: ${rfcs.join(',')}`, async function () {
      assert.ok(rfcs.length)
    })
  })
}

function checkFromNS(type, validRecords, nsName, nsLineName) {
  for (const val of validRecords) {
    const testLine = nsLineName === 'bindline' ? val.testB : val.testT
    if (testLine == undefined) continue
    it(`imports ${nsName} record: ${val.owner}`, async function () {
      const r = new type({ [nsLineName]: testLine })
      if (process.env.DEBUG) console.dir(r)
      for (const f of r.getFields()) {
        if (f === 'class') continue
        let expected = val[f]
        if (f === 'data' && Array.isArray(expected))
          expected = expected.join('') // TXT
        assert.deepStrictEqual(
          r.get(f),
          expected,
          `${f}: ${r.get(f)} !== ${expected}`,
        )
      }
    })
  }
}

export function fromTinydns(type, validRecords) {
  describe('fromTinydns', function () {
    checkFromNS(type, validRecords, 'tinydns', 'tinyline')
  })
}

export function fromBind(type, validRecords) {
  describe('fromBind', function () {
    checkFromNS(type, validRecords, 'BIND', 'bindline')
  })
}

export function getRdataFields(type, rdataFields) {
  describe('getRdataFields', function () {
    const r = new type(null)
    it(`can retrieve rdata fields: (${r.getRdataFields('rdata')})`, async function () {
      assert.deepEqual(r.getRdataFields('rdata'), rdataFields)
    })
  })
}

export function getFields(type, rdataFields) {
  describe('getFields', function () {
    const r = new type(null)
    it(`can retrieve record fields`, async function () {
      assert.deepEqual(r.getFields('rdata'), rdataFields)
      assert.deepEqual(r.getFields(), r.getFields('common').concat(rdataFields))
    })
  })
}

export function getTypeId(type, val) {
  describe('getTypeId', function () {
    const r = new type(null)
    it(`can retrieve record type ID (${r.getTypeId()})`, async function () {
      assert.deepEqual(r.getTypeId(), val)
    })
  })
}
