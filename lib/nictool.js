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

export function getMap(rrType) {
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
  }
}
export function applyMap(obj, map) {
  // map dns-r-r (RFC/IETF) field names to NicTool 2.0 DB fields

  for (const [key, value] of Object.entries(map)) {
    if (Array.isArray(value)) {
      obj[key] = `'${value.map((a) => obj[a]).join("','")}'`
      for (const f of value) {
        delete obj[f]
      }
    } else {
      obj[key] = obj[value]
    }

    delete obj[value]
  }
}
export function unApplyMap(obj, map) {
  // map NicTool 2.0 DB fields to dns-r-r (RFC/IETF) field names
  if (obj.type === 'NAPTR') {
    const [flags, service, regexp] = obj.address.slice(1, -1).split("','")
    obj.flags = flags ?? ''
    obj.service = service ?? ''
    obj.regexp = regexp ?? ''
    delete obj.address
    delete map.address
  }
  if (obj.type === 'NSEC3') {
    const [algo, flags, iters, salt, bitmaps, next] = obj.address.slice(1, -1).split("','")
    obj['hash algorithm'] = /^\d+$/.test(algo) ? parseInt(algo) : (algo ?? '')
    obj.flags = /^\d+$/.test(flags) ? parseInt(flags) : (flags ?? '')
    obj.iterations = /^\d+$/.test(iters) ? parseInt(iters) : (iters ?? '')
    obj.salt = salt
    obj['type bit maps'] = bitmaps
    obj['next hashed owner name'] = next
    delete obj.address
    delete map.address
  }
  if (obj.type === 'NSEC3PARAM') {
    const [algo, flags, iters, salt] = obj.address.slice(1, -1).split("','")
    obj['hash algorithm'] = /^\d+$/.test(algo) ? parseInt(algo) : (algo ?? '')
    obj.flags = /^\d+$/.test(flags) ? parseInt(flags) : (flags ?? '')
    obj.iterations = /^\d+$/.test(iters) ? parseInt(iters) : (iters ?? '')
    obj.salt = salt
    delete obj.address
    delete map.address
  }
  if (obj.type === 'SOA') {
    const [one, two, three, four, five, six, seven] = obj.address.slice(1, -1).split("','")
    obj.mname = one
    obj.rname = two
    obj.serial = parseInt(three)
    obj.refresh = parseInt(four)
    obj.retry = parseInt(five)
    obj.expire = parseInt(six)
    obj.minimum = parseInt(seven)
    delete obj.address
    delete map.address
  }

  for (const [key, value] of Object.entries(map)) {
    switch (value) {
      case 'key tag': // DS record
      case 'port': // SRV
      case 'certificate usage': // SMIMEA
      case 'algorithm': // IPSECKEY
      case 'flags': // KEY
      case 'matching type': // TLSA
        obj[value] = parseInt(obj[key])
        break
      default:
        obj[value] = obj[key]
    }
    delete obj[key]
  }
}
