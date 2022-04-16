
const assert = require('assert')

const RR = require('../index.js').RR

describe('RR', function () {
  const r = new RR(null)

  describe('setTtl', function () {
    const invalid = [ -1, -4, -299, 2147483648, undefined ]
    for (const i of invalid) {
      it(`throws on invalid TTL: ${i}`, async function () {
        try {
          assert.deepStrictEqual(r.setTtl(i), false)
        }
        catch (e) {
          assert.ok(e.message)
          console.error(e.message)
        }
      })
    }
  })

  describe('setClass', function () {
    for (const i of [ 'IN', 'CH', 'ANY', 'NONE' ]) {
      it(`accepts valid class: ${i}`, async function () {
        r.setClass(i)
        assert.deepEqual(r.get('class'), i)
      })
    }

    for (const i of [ 'matt', 'in', 0 ]) {
      it(`throws on invalid class: ${i}`, async function () {
        try {
          assert.strictEqual(r.setClass(i), false)
        }
        catch (e) {
          assert.ok(e.message)
        }
      })
    }
  })

  describe('fullyQualify', function () {
    it('does nothing to empty  hostname', async () => {
      assert.equal(r.fullyQualify(''), '')
    })

    it('fully qualifies a valid hostname', async () => {
      assert.equal(r.fullyQualify('example.com'), 'example.com.')
    })
  })

  describe('getFields', function () {
    it('gets common fields', async function () {
      assert.deepStrictEqual(r.getFields('common'), [ 'owner', 'ttl', 'class', 'type' ])
    })

    it('gets rdata fields', async function () {
      assert.deepStrictEqual(r.getFields('rdata'), [ ]) // none in the parent class
    })
  })

  describe('getFQDN', function () {
    it('adds a period to hostnames', async () => {
      const rr = new RR(null)
      rr.set('owner', 'www.example.com') // bypass FQ check
      assert.equal(rr.getFQDN('owner'), 'www.example.com.')
    })

    it('reduces origin on request', async () => {
      const rr = new RR(null)
      const zone_opts = { origin: 'example.com.', hide: { origin: true } }
      rr.setOwner('www.example.com.')
      assert.equal(rr.getFQDN('owner', zone_opts), 'www')
    })
  })

  describe('isFullyQualified', function () {
    it('should detect FQDNs', async function () {
      assert.deepEqual(r.isFullyQualified('$type', '$field', 'host.example.com.'), true)

      try {
        assert.deepEqual(r.isFullyQualified('$type', '$field', 'host.example.com'), false)
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

  describe('getQuoted', function () {
    it('returns a quoted string', async () => {
      r.set('cpu', '"already quoted"')
      assert.equal(r.get('cpu'), '"already quoted"')
      assert.equal(r.getQuoted('cpu'), '"already quoted"') // doesn't double quote
    })

    it('doesn\'t double quote a quoted string', async () => {
      r.set('cpu', '"already quoted"')
      assert.equal(r.getQuoted('cpu'), '"already quoted"')
    })
  })

  describe('isQuoted', function () {
    it('detects a quoted strings', async function () {
      assert.deepEqual(r.isQuoted('"yes, this is"'), true)
    })

    it('detects non-quoted strings', async function () {
      assert.deepEqual(r.isQuoted('nope, not quoted'), false)
    })
  })

  describe('isValidHostname', function () {
    for (const n of [ 'x', '2x', '*', '*.something' ]) {
      it(`passes name: ${n}`, async function () {
        assert.deepEqual(r.isValidHostname(n), true)
      })
    }
  })
})