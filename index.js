
const fs = require('fs')
const path = require('path')

class RR extends Map {

  constructor (opts) {
    super()
    if (opts === null) return

    if (opts.default) this.default = opts.default

    if (opts.bindline) return this.fromBind(opts.bindline)
    if (opts.tinyline) return this.fromTinydns(opts.tinyline)

    // tinydns specific
    this.setLocation(opts?.location)
    this.setTimestamp(opts?.timestamp)

    this.setOwner(opts?.owner)
    this.setType (opts?.type)
    this.setTtl  (opts?.ttl)
    this.setClass(opts?.class)

    for (const f of this.getFields('rdata')) {
      const fnName = `set${this.ucfirst(f)}`
      if (this[fnName] === undefined) throw new Error(`Missing ${fnName} in class ${this.get('type')}`)
      this[fnName](opts[f])
    }

    if (opts.comment) this.set('comment', opts.comment)
  }

  ucfirst (str) {
    return str.split(/\s/).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('')
  }

  setClass (c) {
    switch (c) {
      case 'IN':    // 1
      case undefined:
      case null:
      case '':
        this.set('class', 'IN')
        break
      case 'CS':    // 2
      case 'CH':    // 3
      case 'HS':    // 4
      case 'NONE':  // 254
      case 'ANY':   // 255
        this.set('class', c)
        break
      default:
        throw new Error(`invalid class ${c}`)
    }
  }

  setLocation (l) {
    switch (l) {
      case undefined:
        return
      default:
        this.set('location', l)
    }
  }

  setTimestamp (l) {
    switch (l) {
      case undefined:
        return
      default:
        this.set('timestamp', l)
    }
  }

  setOwner (n) {
    if (n === undefined) throw new Error(`owner is required`)

    if (n.length < 1 || n.length > 255)
      throw new Error('Domain names must have 1-255 octets (characters): RFC 2181')

    this.isFullyQualified('', 'owner', n)
    this.hasValidLabels(n)

    // wildcard records: RFC 1034, 4592
    if (/\*/.test(n)) {
      if (!/^\*\./.test(n) && !/\.\*\./.test(n)) throw new Error('only *.something or * (by itself) is a valid wildcard')
    }

    this.set('owner', n.toLowerCase())
  }

  setTtl (t) {

    if (t === undefined) t = this?.default?.ttl
    if (t === undefined) {
      if ([ 'SOA', 'SSHPF' ].includes(this.get('type'))) return
      throw new Error('TTL is required, no default available')
    }

    if (typeof t !== 'number') throw new Error(`TTL must be numeric (${typeof t})`)

    // RFC 1035, 2181
    this.is32bitInt(this.owner, 'TTL', t)

    this.set('ttl', t)
  }

  setType (t) {
    if (module.exports[t] === undefined)
      throw new Error(`type ${t} not supported (yet)`)

    this.set('type', t)
  }

  citeRFC () {
    return `see RFC ${this.getRFCs()}`
  }

  fullyQualify (hostname, origin) {
    if (!hostname) return hostname
    if (hostname === '@' && origin) hostname = origin
    if (hostname.endsWith('.')) return hostname.toLowerCase()
    if (origin) return `${hostname}.${origin}`.toLowerCase()
    return `${hostname}.`
  }

  getPrefix (zone_opts = {}) {
    const classVal = zone_opts.hide?.class ? '' : this.get('class')

    let rrTTL = this.get('ttl')
    if (zone_opts.hide?.ttl && rrTTL === zone_opts.ttl) rrTTL = ''

    let owner = this.get('owner')
    if (zone_opts.hide?.sameOwner && zone_opts.previousOwner === owner) {
      owner = ''
    }
    else {
      owner = this.getFQDN('owner', zone_opts)
    }

    return `${owner}\t${rrTTL}\t${classVal}\t${this.get('type')}`
  }

  getPrefixFields () {
    const commonFields = [ 'owner', 'ttl', 'class', 'type' ]
    Object.freeze(commonFields)
    return commonFields
  }

  getEmpty (prop) {
    return this.get(prop) === undefined ? '' : this.get(prop)
  }

  getComment (prop) {
    const c = this.get('comment')
    if (!c || !c[prop]) return ''
    return c[prop]
  }

  getQuoted (prop) {
    // if prop is not in quoted list, return bare
    if (!this.getQuotedFields().includes(prop)) return this.get(prop)

    // if it's already quoted, return as-is
    if (/['"]/.test(this.get(prop)[0])) return this.get(prop)

    return `"${this.get(prop)}"` // add double quotes
  }

  getQuotedFields () {
    return []
  }

  getRdataFields () {
    return []
  }

  getFields (arg) {
    switch (arg) {
      case 'common':
        return this.getPrefixFields()
      case 'rdata':
        return this.getRdataFields()
      default:
        return this.getPrefixFields().concat(this.getRdataFields())
    }
  }

  getFQDN (field, zone_opts = {}) {
    let fqdn = this.get(field)
    if (!fqdn) throw new Error(`empty value for field ${field}`)
    if (!fqdn.endsWith('.')) fqdn += '.'

    if (zone_opts.hide?.origin && zone_opts.origin) {
      if (fqdn === zone_opts.origin) return '@'
      if (fqdn.endsWith(zone_opts.origin)) return fqdn.slice(0, fqdn.length - zone_opts.origin.length - 1)
    }

    return fqdn
  }

  getTinyFQDN (field) {
    const val = this.get(field)
    if (val === '') return val   // empty
    if (val === '.') return val  // null MX

    // strip off trailing ., tinydns doesn't require it for FQDN
    if (val.endsWith('.')) return val.slice(0, -1)

    return val
  }

  getTinydnsGeneric (rdata) {
    return `:${this.getTinyFQDN('owner')}:${this.getTypeId()}:${rdata}:${this.getTinydnsPostamble()}\n`
  }

  getTinydnsPostamble () {
    return [ 'ttl', 'timestamp', 'location' ].map(f => this.getEmpty(f)).join(':')
  }

  hasValidLabels (hostname) {
    // RFC  952 defined valid hostnames
    // RFC 1035 limited domain label chars to letters, digits, and hyphen
    // RFC 1123 allowed hostnames to start with a digit
    // RFC 2181 'any binary string can be used as the label'
    const fq = hostname.endsWith('.') ? hostname.slice(0, -1) : hostname
    for (const label of fq.split('.')) {
      if (label.length < 1 || label.length > 63)
        throw new Error('Labels must have 1-63 octets (characters), RFC 2181')
    }
  }

  is8bitInt (type, field, value) {
    if (typeof value === 'number'
      && parseInt(value, 10) === value  // assure integer
      && value >= 0
      && value <= 255) return true

    throw new Error(`${type} ${field} must be a 8-bit integer (in the range 0-255)`)
  }

  is16bitInt (type, field, value) {
    if (typeof value === 'number'
      && parseInt(value, 10) === value  // assure integer
      && value >= 0
      && value <= 65535) return true

    throw new Error(`${type} ${field} must be a 16-bit integer (in the range 0-65535)`)
  }

  is32bitInt (type, field, value) {
    if (typeof value === 'number'
      && parseInt(value, 10) === value  // assure integer
      && value >= 0
      && value <= 2147483647) return true

    throw new Error(`${type} ${field} must be a 32-bit integer (in the range 0-2147483647)`)
  }

  isQuoted (val) {
    return /^["']/.test(val) && /["']$/.test(val)
  }

  isFullyQualified (type, blah, hostname) {
    if (hostname.endsWith('.')) return true

    throw new Error(`${type}: ${blah} must be fully qualified`)
  }

  isValidHostname (type, field, hostname) {
    const allowed = new RegExp(/[^a-zA-Z0-9\-._/\\]/)
    if (!allowed.test(hostname)) return true

    const matches = allowed.exec(hostname)
    throw new Error(`${type}, ${field} has invalid hostname character (${matches[0]})`)
  }

  toBind (zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.getRdataFields().map(f => this.getQuoted(f)).join('\t')}\n`
  }

  toMaraDNS () {
    const type = this.get('type')
    const supportedTypes = 'A PTR MX AAAA SRV NAPTR NS SOA TXT SPF RAW FQDN4 FQDN6 CNAME HINFO WKS LOC'.split(/\s+/g)
    if (!supportedTypes.includes(type)) return this.toMaraGeneric()
    return `${this.get('owner')}\t+${this.get('ttl')}\t${type}\t${this.getRdataFields().map(f => this.getQuoted(f)).join('\t')} ~\n`
  }

  toMaraGeneric () {
    // throw new Error(`\nMaraDNS does not support ${type} records yet and this package does not support MaraDNS generic records. Yet.\n`)
    return `${this.get('owner')}\t+${this.get('ttl')}\tRAW ${this.getTypeId()}\t'${this.getRdataFields().map(f => this.getQuoted(f)).join(' ')}' ~\n`
  }
}

module.exports = {
  RR,
  TINYDNS : require('./lib/tinydns'),
  TYPE_MAP: {},
}

const files = fs.readdirSync(path.join('rr'))
for (let f of files) {
  if (!f.endsWith('.js')) continue
  f = path.basename(f, '.js')
  if (f === 'index') continue
  const rrTypeName = f.toUpperCase()
  module.exports[rrTypeName] = require(`./rr/${f}`)
  // module.exports.TYPE_MAP[inst.getTypeId()] = rrTypeName
}
