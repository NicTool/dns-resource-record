/**
 * NicTool 2.x storage columns <-> RFC/IETF resource-record field names.
 *
 * NicTool stores every record type in the same handful of columns — `address`
 * holds the rdata, with `weight`, `priority`, `other` and `description` reused
 * per type — while this library names fields as the RFCs do. These maps
 * translate between the two, so a record read straight from the NicTool schema
 * can be handed to the matching RR class and exported with toBind() or
 * toTinydns().
 *
 * Types whose rdata packs several fields into `address` (NAPTR, NSEC3, SOA...)
 * are unpacked explicitly in unApplyMap.
 */

/**
 * Values are arrays for the packed types, so freeze those too. Freezing makes
 * the caches safe to share: mutating a map is a TypeError under ESM's strict mode
 */
function freezeMap(map) {
  for (const value of Object.values(map)) {
    if (Array.isArray(value)) Object.freeze(value)
  }
  return Object.freeze(map)
}

// A zone export maps once per record — millions of them for a large install —
// so build each type's map, and its entries, once.
const mapCache = new Map()
const entriesCache = new WeakMap()

function mapEntries(map) {
  let entries = entriesCache.get(map)
  if (entries === undefined) {
    entries = Object.entries(map)
    entriesCache.set(map, entries)
  }
  return entries
}

export function getMap(rrType) {
  let map = mapCache.get(rrType)
  if (map === undefined) {
    map = freezeMap(mapFor(rrType))
    mapCache.set(rrType, map)
  }
  return map
}

function mapFor(rrType) {
  switch (rrType) {
    case 'CAA':
      return {
        weight: 'flags',
        other: 'tag',
        address: 'value',
      }
    case 'CERT':
      return {
        other: 'cert type',
        priority: 'key tag',
        weight: 'algorithm',
        address: 'certificate',
      }
    case 'CNAME':
      return { address: 'cname' }
    case 'DNAME':
      return { address: 'target' }
    case 'DNSKEY':
      return {
        address: 'publickey',
        weight: 'flags',
        priority: 'protocol',
        other: 'algorithm',
      }
    case 'DS':
      return {
        address: 'digest',
        weight: 'digest type',
        priority: 'algorithm',
        other: 'key tag',
      }
    case 'HINFO':
      return { address: 'os', other: 'cpu' }
    case 'HTTPS':
      return {
        address: 'target name',
        other: 'params',
      }
    case 'IPSECKEY':
      return {
        address: 'gateway',
        description: 'publickey',
        weight: 'precedence',
        priority: 'gateway type',
        other: 'algorithm',
      }
    case 'KEY':
      return {
        address: 'publickey',
        weight: 'protocol',
        priority: 'algorithm',
        other: 'flags',
      }
    case 'MX':
      return { weight: 'preference', address: 'exchange' }
    case 'NAPTR':
      return {
        weight: 'order',
        priority: 'preference',
        address: ['flags', 'service', 'regexp'],
        description: 'replacement',
      }
    case 'NS':
      return { address: 'dname' }
    case 'NSEC':
      return {
        address: 'next domain',
        description: 'type bit maps',
      }
    case 'NSEC3':
      return {
        address: ['hash algorithm', 'flags', 'iterations', 'salt', 'type bit maps', 'next hashed owner name'],
      }
    case 'NSEC3PARAM':
      return {
        address: ['hash algorithm', 'flags', 'iterations', 'salt'],
      }
    case 'NXT':
      return {
        address: 'next domain',
        description: 'type bit map',
      }
    case 'OPENPGPKEY':
      return { address: 'public key' }
    case 'PTR':
      return { address: 'dname' }
    case 'SMIMEA':
      return {
        address: 'certificate association data',
        weight: 'matching type',
        priority: 'selector',
        other: 'certificate usage',
      }
    case 'SOA':
      return {
        address: ['mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum'],
      }
    case 'SPF':
      return { address: 'data' }
    case 'SSHFP':
      return {
        address: 'fingerprint',
        weight: 'algorithm',
        priority: 'fptype',
      }
    case 'SRV':
      return { address: 'target', other: 'port' }
    case 'SVCB':
      return {
        address: 'target name',
        other: 'params',
      }
    case 'TLSA':
      return {
        weight: 'certificate usage',
        priority: 'selector',
        address: 'certificate association data',
        other: 'matching type',
      }
    case 'TXT':
      return { address: 'data' }
    case 'URI':
      return { address: 'target' }
    default:
      // Types NicTool stores without column overloading need no translation.
      return {}
  }
}

export function applyMap(obj, map) {
  // map dns-r-r (RFC/IETF) field names to NicTool 2.0 DB fields

  for (const [key, value] of mapEntries(map)) {
    if (Array.isArray(value)) {
      obj[key] = `'${value.map((a) => obj[a]).join("','")}'`
      for (const f of value) {
        delete obj[f]
      }
      // No `delete obj[value]` here: an array key stringifies to
      // "flags,service,regexp" and would delete an unrelated property.
      continue
    }

    obj[key] = obj[value]
    delete obj[value]
  }
}

// Integers on the wire. `certtype` is numeric but also accepts mnemonics
// ("PKIX"), so a value is converted only when it actually looks numeric —
// the declared format alone is not enough.
const NUMERIC_FORMATS = new Set(['u8', 'u16', 'u32', 'certtype'])

/**
 * type -> the fields that class declares as integers, from its static
 * rdataFields. NicTool's `other` column is VARCHAR, so MySQL hands back "1"
 * where the RR setter demands an integer; `weight` and `priority` are SMALLINT
 * and only arrive as strings from a file store or hand-edited data.
 *
 * Keyed on the type because a bare field name is ambiguous: `flags` is u8 in
 * CAA, u16 in DNSKEY and a character string in NAPTR.
 *
 * Populated by index.js, which is where the classes are already enumerated;
 * importing them here would close an import cycle.
 */
const numericFields = new Map()

export function registerRdataFormats(classes) {
  for (const rrClass of classes) {
    const numeric = new Set()
    for (const entry of rrClass.rdataFields ?? []) {
      if (Array.isArray(entry) && NUMERIC_FORMATS.has(entry[1])) numeric.add(entry[0])
    }
    numericFields.set(rrClass.typeName, numeric)
  }
}

export function unApplyMap(obj, map) {
  // map NicTool 2.0 DB fields to dns-r-r (RFC/IETF) field names
  let packed = false

  if (obj.type === 'NAPTR') {
    const [flags, service, regexp] = obj.address.slice(1, -1).split("','")
    obj.flags = flags ?? ''
    obj.service = service ?? ''
    obj.regexp = regexp ?? ''
    delete obj.address
    packed = true
  }
  if (obj.type === 'NSEC3') {
    const [algo, flags, iters, salt, bitmaps, next] = obj.address.slice(1, -1).split("','")
    obj['hash algorithm'] = /^\d+$/.test(algo) ? parseInt(algo, 10) : (algo ?? '')
    obj.flags = /^\d+$/.test(flags) ? parseInt(flags, 10) : (flags ?? '')
    obj.iterations = /^\d+$/.test(iters) ? parseInt(iters, 10) : (iters ?? '')
    obj.salt = salt
    obj['type bit maps'] = bitmaps
    obj['next hashed owner name'] = next
    delete obj.address
    packed = true
  }
  if (obj.type === 'NSEC3PARAM') {
    const [algo, flags, iters, salt] = obj.address.slice(1, -1).split("','")
    obj['hash algorithm'] = /^\d+$/.test(algo) ? parseInt(algo, 10) : (algo ?? '')
    obj.flags = /^\d+$/.test(flags) ? parseInt(flags, 10) : (flags ?? '')
    obj.iterations = /^\d+$/.test(iters) ? parseInt(iters, 10) : (iters ?? '')
    obj.salt = salt
    delete obj.address
    packed = true
  }
  if (obj.type === 'SOA') {
    const [one, two, three, four, five, six, seven] = obj.address.slice(1, -1).split("','")
    obj.mname = one
    obj.rname = two
    obj.serial = parseInt(three, 10)
    obj.refresh = parseInt(four, 10)
    obj.retry = parseInt(five, 10)
    obj.expire = parseInt(six, 10)
    obj.minimum = parseInt(seven, 10)
    delete obj.address
    packed = true
  }

  const numeric = numericFields.get(obj.type)

  for (const [key, value] of mapEntries(map)) {
    if (packed && key === 'address') continue
    const stored = obj[key]
    // Only a string can need converting, and skipping the rest keeps the
    // numeric columns MySQL already types correctly off this path entirely.
    obj[value] =
      typeof stored === 'string' && numeric?.has(value) && /^\d+$/.test(stored)
        ? parseInt(stored, 10)
        : stored
    delete obj[key]
  }
}
