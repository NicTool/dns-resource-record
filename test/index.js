
const assert = require('assert')

const RR = require('../rr/index').RR

describe('RR', function () {
  const r = new RR(null)

  describe('getFields', function () {
    it('gets common fields', async function () {
      assert.deepStrictEqual(r.getFields('common'), [ 'name', 'ttl', 'class', 'type' ])
    })

    it('gets rdata fields', async function () {
      assert.deepStrictEqual(r.getFields('rdata'), [ ]) // none in the parent class
    })
  })

  describe('fullyQualified', function () {
    it('should detect FQDNs', async function () {
      assert.deepEqual(r.fullyQualified('$type', '$field', 'host.example.com.'), true)

      try {
        assert.deepEqual(r.fullyQualified('$type', '$field', 'host.example.com'), false)
      }
      catch (e) {
        assert.deepEqual(e.message, '$type: $field must be fully qualified')
      }
    })
  })

  describe('is8bitInt', function () {
    const valid = [ 1, 2, 255 ]
    const invalid = [ -1, 'a', new Date(), undefined, 256 ]

    for (const i of valid) {
      it(`returns true for valid int: ${i}`, async function () {
        assert.strictEqual(r.is8bitInt('test', 'field', i), true)
      })
    }

    for (const i of invalid) {
      it(`throws on invalid int: ${i}`, async function () {
        try {
          assert.strictEqual(r.is8bitInt('test', 'field', i), false)
        }
        catch (e) {
          assert.strictEqual(e.message, 'test field must be a 8-bit integer (in the range 0-255)')
        }
      })
    }
  })

  describe('is16bitInt', function () {
    const valid = [ 0, 1, 2, 55555, 65535 ]
    const invalid = [ 'a', new Date(), undefined, 65536 ]

    for (const i of valid) {
      it(`returns true for valid int: ${i}`, async function () {
        assert.strictEqual(r.is16bitInt('test', 'field', i), true)
      })
    }

    for (const i of invalid) {
      it(`throws on invalid int: ${i}`, async function () {
        try {
          assert.strictEqual(r.is16bitInt('test', 'field', i), false)
        }
        catch (e) {
          assert.strictEqual(e.message, 'test field must be a 16-bit integer (in the range 0-65535)')
        }
      })
    }
  })

  describe('is32bitInt', function () {
    const valid = [ 1, 2, 55555, 2147483647 ]
    const invalid = [ 'a', new Date(), undefined, 2147483648 ]

    for (const i of valid) {
      it(`returns true for valid int: ${i}`, async function () {
        assert.strictEqual(r.is32bitInt('test', 'field', i), true)
      })
    }

    for (const i of invalid) {
      it(`throws on invalid int: ${i}`, async function () {
        try {
          assert.strictEqual(r.is32bitInt('test', 'field', i), false)
        }
        catch (e) {
          assert.strictEqual(e.message, 'test field must be a 32-bit integer (in the range 0-2147483647)')
        }
      })
    }
  })

  describe('isQuoted', function () {
    it('detects a quoted strings', async function () {
      assert.deepEqual(r.isQuoted('"yes, this is"'), true)
    })

    it('detects non-quoted strings', async function () {
      assert.deepEqual(r.isQuoted('nope, not quoted'), false)
    })
  })
})