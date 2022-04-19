
import assert from 'assert'

import * as RR from '../index.js'

// import * as base from './base.js'

const defaults = { owner: 'fake.com.', class: 'IN', ttl: 3600, address: '192.0.2.127' }

describe('fake', function () {
  it(`throws on invalid RR class`, async function () {
    assert.throws(() => {
      new RR.fake({ ...defaults, type: 'A' })
    },
    {
      message: /fake is not a constructor/,
    })
  })

  it(`throws on invalid RR type`, async function () {
    assert.throws(() => {
      new RR.A({ ...defaults, type: 'NONEXIST' })
    },
    {
      message: /type NONEXIST doesn't match A/,
    })
  })
})