// NicTool column <-> RFC field mapping.
//
// NicTool stores every record type in the same few columns — `address` holds
// the rdata, with `weight`, `priority` and `other` reused per type. These maps
// translate to the field names this library uses, so a record read from the
// NicTool schema can be handed straight to the matching RR class.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { applyMap, getMap, unApplyMap } from '../index.js'

/** Storage shape -> RFC shape, as a reader does. */
const toRfc = (row) => {
  const obj = { ...row }
  unApplyMap(obj, getMap(obj.type))
  return obj
}

/** RFC shape -> storage shape, as a writer does. */
const toStorage = (obj) => {
  const row = { ...obj }
  applyMap(row, getMap(row.type))
  return row
}

describe('getMap', () => {
  it('maps the overloaded columns for a simple type', () => {
    assert.deepEqual(getMap('CNAME'), { address: 'cname' })
  })

  it('maps several columns for a multi-field type', () => {
    assert.deepEqual(getMap('SRV'), { address: 'target', other: 'port' })
  })

  it('returns an empty map for a type needing no translation', () => {
    // A/AAAA already call their rdata `address`, so there is nothing to rename.
    assert.deepEqual(getMap('A'), {})
  })

  it('returns an empty map for an unknown type rather than undefined', () => {
    // Callers iterate the result; undefined would throw.
    assert.deepEqual(getMap('NOSUCHTYPE'), {})
    assert.doesNotThrow(() => Object.entries(getMap('NOSUCHTYPE')))
  })
})

// Every type getMap declares. Kept explicit so a new case must be added here
// too, which is where you notice it needs a mapping test.
const MAPPED_TYPES = [
  'CAA',
  'CERT',
  'CNAME',
  'DNAME',
  'DNSKEY',
  'DS',
  'HINFO',
  'HTTPS',
  'IPSECKEY',
  'KEY',
  'MX',
  'NAPTR',
  'NS',
  'NSEC',
  'NSEC3',
  'NSEC3PARAM',
  'NXT',
  'OPENPGPKEY',
  'PTR',
  'SMIMEA',
  'SOA',
  'SPF',
  'SSHFP',
  'SRV',
  'SVCB',
  'TLSA',
  'TXT',
  'URI',
]

describe('every mapped type', () => {
  it('returns a usable map', () => {
    for (const type of MAPPED_TYPES) {
      const map = getMap(type)
      assert.equal(typeof map, 'object', `${type} must map to an object`)
      assert.ok(Object.keys(map).length > 0, `${type} is listed but maps nothing`)
    }
  })

  it('only ever renames the columns NicTool overloads', () => {
    // A mapping keyed on anything else would silently drop or invent a column.
    const columns = new Set(['address', 'weight', 'priority', 'other', 'description'])

    for (const type of MAPPED_TYPES) {
      for (const key of Object.keys(getMap(type))) {
        assert.ok(columns.has(key), `${type} maps unknown column "${key}"`)
      }
    }
  })

  it('never maps two columns onto the same field', () => {
    for (const type of MAPPED_TYPES) {
      const targets = Object.values(getMap(type)).flat()
      assert.equal(new Set(targets).size, targets.length, `${type} maps two columns to the same field`)
    }
  })
})

describe('unApplyMap', () => {
  it('renames a single column', () => {
    const rr = toRfc({ type: 'CNAME', address: 'www.example.com.' })

    assert.equal(rr.cname, 'www.example.com.')
    assert.equal(rr.address, undefined)
  })

  it('renames several, coercing the numeric ones', () => {
    const rr = toRfc({ type: 'SRV', address: 'sip.example.com.', other: '5060' })

    assert.equal(rr.target, 'sip.example.com.')
    assert.equal(rr.port, 5060, 'port is numeric, not the "5060" the column holds')
  })

  it('unpacks NAPTR, whose three fields share one column', () => {
    const rr = toRfc({
      type: 'NAPTR',
      address: "'U','E2U+sip','!^.*$!sip:x@example.com!'",
      weight: 100,
      priority: 10,
    })

    assert.equal(rr.flags, 'U')
    assert.equal(rr.service, 'E2U+sip')
    assert.equal(rr.regexp, '!^.*$!sip:x@example.com!')
    assert.equal(rr.address, undefined)
  })

  it('unpacks NSEC3, coercing its numeric fields', () => {
    const rr = toRfc({
      type: 'NSEC3',
      address: "'1','0','12','aabbccdd','A NS SOA','2vptu5timamqttgl4luu9kg21e0aor3s'",
    })

    assert.equal(rr['hash algorithm'], 1)
    assert.equal(rr.iterations, 12)
    assert.equal(rr.salt, 'aabbccdd')
    assert.equal(rr['next hashed owner name'], '2vptu5timamqttgl4luu9kg21e0aor3s')
  })

  it('numbers a field the `other` VARCHAR column hands back as a string', () => {
    // CERT reads `cert type` from `other`, so MySQL returns "1"; the setter
    // requires an integer and threw before this was coerced.
    const rr = toRfc({ type: 'CERT', other: '1', priority: 1234, weight: 3, address: 'AQ==' })

    assert.equal(rr['cert type'], 1)
    assert.equal(rr['key tag'], 1234)
  })

  it('leaves a mnemonic alone rather than parsing it to NaN', () => {
    // CERT accepts "PKIX" as well as 1, so coercion has to be conditional.
    const rr = toRfc({ type: 'CERT', other: 'PKIX', priority: 1234, weight: 3, address: 'AQ==' })

    assert.equal(rr['cert type'], 'PKIX')
  })

  it('numbers every field whose RR setter demands an integer', () => {
    // Each of these is validated with Number.isInteger downstream; a string
    // reaching the setter throws, which is silent data loss on export.
    const cases = [
      ['DS', { weight: '1', priority: '5', other: '60485' }, ['digest type', 'algorithm', 'key tag']],
      [
        'TLSA',
        { weight: '3', priority: '1', other: '1' },
        ['certificate usage', 'selector', 'matching type'],
      ],
      ['SSHFP', { weight: '2', priority: '1' }, ['algorithm', 'fptype']],
      ['IPSECKEY', { weight: '10', priority: '1', other: '2' }, ['precedence', 'gateway type', 'algorithm']],
      ['DNSKEY', { weight: '256', priority: '3', other: '5' }, ['flags', 'protocol', 'algorithm']],
      ['MX', { weight: '10' }, ['preference']],
      ['SRV', { other: '5060' }, ['port']],
    ]

    for (const [type, row, fields] of cases) {
      const rr = toRfc({ type, address: 'x.test.', ...row })
      for (const f of fields) {
        assert.equal(typeof rr[f], 'number', `${type} ${f} must be numeric, got ${typeof rr[f]}`)
      }
    }
  })

  it('decides by the type’s declared format, not the field name', () => {
    // `flags` is u8 in CAA, u16 in DNSKEY and a character string in NAPTR, so
    // a name-keyed rule would coerce a NAPTR flag of "0" into a number.
    assert.equal(toRfc({ type: 'CAA', weight: '0', other: 'issue', address: 'x.org' }).flags, 0)
    assert.equal(
      toRfc({ type: 'DNSKEY', weight: '256', priority: '3', other: '5', address: 'AQ==' }).flags,
      256,
    )

    const naptr = toRfc({ type: 'NAPTR', address: "'0','E2U+sip','!x!'", weight: 1, priority: 2 })
    assert.equal(naptr.flags, '0', 'NAPTR flags is a character string')
  })

  it('leaves a character-string field alone when its value looks numeric', () => {
    // CAA `tag` is a charstr; "123" is a tag, not the number 123.
    const rr = toRfc({ type: 'CAA', weight: 0, other: '123', address: 'x.org' })

    assert.equal(rr.tag, '123')
  })

  it('unpacks NSEC3PARAM, which shares NSEC3 fields but has no bitmaps', () => {
    const rr = toRfc({ type: 'NSEC3PARAM', address: "'1','0','12','aabbccdd'" })

    assert.equal(rr['hash algorithm'], 1)
    assert.equal(rr.flags, 0)
    assert.equal(rr.iterations, 12)
    assert.equal(rr.salt, 'aabbccdd')
    assert.equal(rr.address, undefined)
  })

  it('unpacks a type whose rdata is packed into `address`', () => {
    const rr = toRfc({
      type: 'SOA',
      address: "'ns1.example.com.','hostmaster.example.com.','1','7200','3600','1209600','3600'",
    })

    assert.equal(rr.mname, 'ns1.example.com.')
    assert.equal(rr.rname, 'hostmaster.example.com.')
    assert.equal(rr.serial, 1)
    assert.equal(rr.minimum, 3600)
    assert.equal(rr.address, undefined)
  })
})

describe('applyMap', () => {
  it('packs the RFC fields back into the storage columns', () => {
    // getMap('MX') is { weight: 'preference', address: 'exchange' } — the key
    // is the NicTool column, the value the RFC field.
    const row = toStorage({ type: 'MX', exchange: 'mail.example.com.', preference: 10 })

    assert.equal(row.address, 'mail.example.com.', 'exchange -> address')
    assert.equal(row.weight, 10, 'preference -> weight')
    assert.equal(row.exchange, undefined)
    assert.equal(row.preference, undefined)
  })

  it('joins a packed type into a single column', () => {
    const row = toStorage({
      type: 'NAPTR',
      flags: 'U',
      service: 'E2U+sip',
      regexp: '!^.*$!sip:x@example.com!',
      order: 100,
      preference: 10,
    })

    assert.match(row.address, /^'U','E2U\+sip','!\^/)
    assert.equal(row.flags, undefined)
    assert.equal(row.service, undefined)
  })

  it('does not delete an unrelated property for a packed type', () => {
    // The array key stringifies to "flags,service,regexp"; deleting by it
    // would remove whatever happened to be stored under that name.
    const row = {
      type: 'NAPTR',
      flags: 'U',
      service: 'E2U+sip',
      regexp: '!x!',
      'flags,service,regexp': 'must survive',
    }
    applyMap(row, getMap('NAPTR'))

    assert.equal(row['flags,service,regexp'], 'must survive')
  })
})

describe('map reuse', () => {
  it('returns a frozen map, so mutating it fails loudly', () => {
    // Under ESM's strict mode this is a TypeError rather than a silent no-op,
    // which is what makes the guarantee below worth having.
    const map = getMap('SOA')

    assert.equal(Object.isFrozen(map), true)
    assert.equal(Object.isFrozen(map.address), true, 'packed types hold arrays')
    assert.throws(() => delete map.address, TypeError)
    assert.throws(() => {
      map.other = 'x'
    }, TypeError)
  })

  it('leaves a caller-held map intact for a packed type', () => {
    // getMap is public, so a caller may cache the map; unApplyMap used to
    // delete from it, breaking every later use.
    const map = getMap('SOA')
    const before = JSON.stringify(map)

    unApplyMap({ type: 'SOA', address: "'ns1.x.','host.x.','1','2','3','4','5'" }, map)

    assert.equal(JSON.stringify(map), before)
  })

  it('gives the same result when a map is used twice', () => {
    const map = getMap('SOA')
    const rows = [
      { type: 'SOA', address: "'ns1.x.','host.x.','1','2','3','4','5'" },
      { type: 'SOA', address: "'ns2.y.','host.y.','9','2','3','4','5'" },
    ]
    for (const r of rows) unApplyMap(r, map)

    assert.equal(rows[0].mname, 'ns1.x.')
    assert.equal(rows[1].mname, 'ns2.y.')
    assert.equal(rows[1].address, undefined)
  })
})

describe('round trip', () => {
  it('storage -> RFC -> storage for a simple type', () => {
    const stored = { type: 'CNAME', address: 'www.example.com.' }

    assert.deepEqual(toStorage(toRfc(stored)), stored)
  })

  it('storage -> RFC -> storage for a multi-column type', () => {
    const rfc = toRfc({ type: 'SRV', address: 'sip.example.com.', other: '5060' })
    const back = toStorage(rfc)

    assert.equal(back.address, 'sip.example.com.')
    assert.equal(back.other, 5060)
  })

  it('RFC -> storage -> RFC for a packed type', () => {
    const rfc = {
      type: 'SOA',
      mname: 'ns1.example.com.',
      rname: 'hostmaster.example.com.',
      serial: 1,
      refresh: 7200,
      retry: 3600,
      expire: 1209600,
      minimum: 3600,
    }

    assert.deepEqual(toRfc(toStorage(rfc)), rfc)
  })
})
