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

const assertHas = (obj, expected, msg) => {
  for (const [k, v] of Object.entries(expected)) assert.deepEqual(obj[k], v, `${msg ?? obj.type} ${k}`)
}

// Every type getMap declares. Kept explicit so a new case must be added here
// too, which is where you notice it needs a mapping test.
const MAPPED_TYPES = [
  ...'CAA CERT CNAME DNAME DNSKEY DS HINFO HTTPS IPSECKEY KEY MX NAPTR NS NSEC'.split(' '),
  ...'NSEC3 NSEC3PARAM NXT OPENPGPKEY PTR SMIMEA SOA SPF SSHFP SRV SVCB TLSA TXT URI'.split(' '),
]

describe('getMap', () => {
  it('maps the overloaded columns', () => {
    assert.deepEqual(getMap('CNAME'), { address: 'cname' })
    assert.deepEqual(getMap('SRV'), { address: 'target', other: 'port' })
    // A/AAAA already call their rdata `address`, so there is nothing to rename.
    assert.deepEqual(getMap('A'), {})
    // Callers iterate the result; undefined would throw.
    assert.deepEqual(getMap('NOSUCHTYPE'), {})
  })

  it('maps every listed type to distinct fields from the columns NicTool overloads', () => {
    // A mapping keyed on anything else would silently drop or invent a column.
    const columns = new Set(['address', 'weight', 'priority', 'other', 'description'])
    for (const type of MAPPED_TYPES) {
      const map = getMap(type)
      assert.ok(Object.keys(map).length > 0, `${type} is listed but maps nothing`)
      for (const key of Object.keys(map)) assert.ok(columns.has(key), `${type} maps unknown column "${key}"`)
      const targets = Object.values(map).flat()
      assert.equal(new Set(targets).size, targets.length, `${type} maps two columns to the same field`)
    }
  })
})

describe('unApplyMap', () => {
  it('renames columns, unpacking and numbering fields', () => {
    for (const [row, expected] of [
      [
        { type: 'CNAME', address: 'www.example.com.' },
        { cname: 'www.example.com.', address: undefined },
      ],
      [
        { type: 'SRV', address: 'sip.example.com.', other: '5060' },
        { target: 'sip.example.com.', port: 5060 },
      ],
      // NAPTR's three character-strings share one column
      [
        { type: 'NAPTR', address: "'U','E2U+sip','!^.*$!sip:x@example.com!'", weight: 100, priority: 10 },
        { flags: 'U', service: 'E2U+sip', regexp: '!^.*$!sip:x@example.com!', address: undefined },
      ],
      [
        { type: 'NSEC3', address: "'1','0','12','aabbccdd','A NS SOA','2vptu5timamqttgl4luu9kg21e0aor3s'" },
        {
          'hash algorithm': 1,
          iterations: 12,
          salt: 'aabbccdd',
          'next hashed owner name': '2vptu5timamqttgl4luu9kg21e0aor3s',
        },
      ],
      // NSEC3PARAM shares NSEC3 fields but has no bitmaps
      [
        { type: 'NSEC3PARAM', address: "'1','0','12','aabbccdd'" },
        { 'hash algorithm': 1, flags: 0, iterations: 12, salt: 'aabbccdd', address: undefined },
      ],
      [
        {
          type: 'SOA',
          address: "'ns1.example.com.','hostmaster.example.com.','1','7200','3600','1209600','3600'",
        },
        {
          mname: 'ns1.example.com.',
          rname: 'hostmaster.example.com.',
          serial: 1,
          minimum: 3600,
          address: undefined,
        },
      ],
      // CERT reads `cert type` from the `other` VARCHAR, so MySQL returns "1",
      // but it also accepts the mnemonic "PKIX", which must not become NaN.
      [
        { type: 'CERT', other: '1', priority: 1234, weight: 3, address: 'AQ==' },
        { 'cert type': 1, 'key tag': 1234 },
      ],
      [{ type: 'CERT', other: 'PKIX', priority: 1234, weight: 3, address: 'AQ==' }, { 'cert type': 'PKIX' }],
      // CAA `tag` is a charstr; "123" is a tag, not the number 123.
      [{ type: 'CAA', weight: 0, other: '123', address: 'x.org' }, { tag: '123' }],
    ]) {
      assertHas(toRfc(row), expected)
    }
  })

  it('numbers every field whose RR setter demands an integer', () => {
    // A string reaching one of these setters throws, which is silent data loss on export.
    for (const [type, row, fields] of [
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
    ]) {
      const rr = toRfc({ type, address: 'x.test.', ...row })
      for (const f of fields) assert.equal(typeof rr[f], 'number', `${type} ${f}`)
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
    assert.equal(toRfc({ type: 'NAPTR', address: "'0','E2U+sip','!x!'", weight: 1, priority: 2 }).flags, '0')
  })
})

describe('applyMap', () => {
  it('packs the RFC fields back into the storage columns', () => {
    // the map key is the NicTool column, the value the RFC field
    assertHas(toStorage({ type: 'MX', exchange: 'mail.example.com.', preference: 10 }), {
      address: 'mail.example.com.',
      weight: 10,
      exchange: undefined,
      preference: undefined,
    })

    const naptr = toStorage({
      type: 'NAPTR',
      flags: 'U',
      service: 'E2U+sip',
      regexp: '!^.*$!sip:x@example.com!',
      order: 100,
      preference: 10,
    })
    assert.match(naptr.address, /^'U','E2U\+sip','!\^/)
    assertHas(naptr, { flags: undefined, service: undefined })
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
    // Under ESM's strict mode this is a TypeError rather than a silent no-op.
    const map = getMap('SOA')
    assert.equal(Object.isFrozen(map), true)
    assert.equal(Object.isFrozen(map.address), true, 'packed types hold arrays')
    assert.throws(() => delete map.address, TypeError)
    assert.throws(() => {
      map.other = 'x'
    }, TypeError)
  })

  it('leaves a caller-held map intact and reusable', () => {
    // getMap is public, so a caller may cache the map.
    const map = getMap('SOA')
    const before = JSON.stringify(map)
    const rows = [
      { type: 'SOA', address: "'ns1.x.','host.x.','1','2','3','4','5'" },
      { type: 'SOA', address: "'ns2.y.','host.y.','9','2','3','4','5'" },
    ]
    for (const r of rows) unApplyMap(r, map)
    assert.equal(JSON.stringify(map), before)
    assertHas(rows[0], { mname: 'ns1.x.' })
    assertHas(rows[1], { mname: 'ns2.y.', address: undefined })
  })
})

it('round trips between storage and RFC shapes', () => {
  const cname = { type: 'CNAME', address: 'www.example.com.' }
  assert.deepEqual(toStorage(toRfc(cname)), cname)

  assertHas(toStorage(toRfc({ type: 'SRV', address: 'sip.example.com.', other: '5060' })), {
    address: 'sip.example.com.',
    other: 5060,
  })

  const soa = {
    type: 'SOA',
    mname: 'ns1.example.com.',
    rname: 'hostmaster.example.com.',
    serial: 1,
    refresh: 7200,
    retry: 3600,
    expire: 1209600,
    minimum: 3600,
  }
  assert.deepEqual(toRfc(toStorage(soa)), soa)
})
