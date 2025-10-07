import assert from 'node:assert/strict'

export function valid(type, validRecords) {
  describe('valid', function () {
    for (const val of validRecords) {
      // console.log(val)
      it(`parses record: ${val.owner}`, function () {
        const r = new type(val)
        if (process.env.DEBUG) console.dir(r)

        for (const k of Object.keys(val)) {
          if (/^test/.test(k)) continue
          assert.equal(r.get(k), val[k], `${type.name} ${k} ${r.get(k)} !== ${val[k]}`)
        }
      })
    }
  })
}

export function invalid(type, invalidRecords) {
  describe('invalid', function () {
    for (const inv of invalidRecords) {
      it(`throws on record (${inv.owner})`, function () {
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
      it(`exports to BIND: ${val.owner}`, function () {
        const r = new type(val).toBind()
        if (process.env.DEBUG) console.dir(r)
        assert.equal(r, val.testB)
      })
    }
  })
}

export function toTinydns(type, validRecords) {
  describe('toTinydns', function () {
    for (const val of validRecords) {
      if (val.testT === undefined) continue
      it(`exports to tinydns: ${val.owner}`, function () {
        const r = new type(val).toTinydns()
        if (process.env.DEBUG) console.dir(r)
        assert.equal(r, val.testT)
      })
    }
  })
}

export function getDescription(type) {
  describe('getDescription', function () {
    const desc = new type(null).getDescription()
    it(`gets description: ${desc}`, function () {
      assert.ok(desc)
    })
  })
}

export function getRFCs(type, valid) {
  describe('getRFCs', function () {
    const r = new type(null)
    const rfcs = r.getRFCs()
    it(`can retrieve RFCs: ${rfcs.join(',')}`, function () {
      assert.ok(rfcs.length)
    })
  })
}

function checkFromNS(type, validRecords, nsName, nsLineName) {
  for (const val of validRecords) {
    const testLine = nsLineName === 'bindline' ? val.testB : val.testT
    if (testLine == undefined) continue
    it(`imports ${nsName} record: ${val.owner}`, function () {
      const r = new type({ [nsLineName]: testLine })
      if (process.env.DEBUG) console.dir(r)
      for (const f of r.getFields()) {
        if (f === 'class') continue
        let expected = val[f]
        if (f === 'data' && Array.isArray(expected)) expected = expected.join('') // TXT
        assert.deepEqual(r.get(f), expected, `${f}: ${r.get(f)} !== ${expected}`)
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
    it(`can retrieve rdata fields: (${r.getRdataFields('rdata')})`, function () {
      assert.deepEqual(r.getRdataFields('rdata'), rdataFields)
    })
  })
}

export function getFields(type, rdataFields) {
  describe('getFields', function () {
    const r = new type(null)
    it(`can retrieve record fields`, function () {
      assert.deepEqual(r.getFields('rdata'), rdataFields)
      assert.deepEqual(r.getFields(), r.getFields('common').concat(rdataFields))
    })
  })
}

export function getTypeId(type, val) {
  describe('getTypeId', function () {
    const r = new type(null)
    it(`can retrieve record type ID (${r.getTypeId()})`, function () {
      assert.deepEqual(r.getTypeId(), val)
    })
  })
}
