import { inspect } from 'util'
import * as TINYDNS from './lib/tinydns.js'
import {
  wireUnpackDomain,
  wirePackDomain,
  getWireRdata as wireGetRdata,
  toWire as wireToWire,
  fromWireBytes,
  fromWireGeneric,
} from './lib/wire.js'
import {
  parseBindLine as bindParseLine,
  fromBind as bindFromGeneric,
  toBind as bindToGeneric,
} from './lib/bind.js'

export default class RR {
  static CLASSES = { IN: 1, CS: 2, CH: 3, HS: 4, NONE: 254, ANY: 255 }
  static typeId
  static RFCs = []
  static tags = []

  constructor(opts) {
    if (opts === null) return

    if (opts?.default) this.default = opts.default

    // tinydns specific
    this.setLocation(opts?.location)
    this.setTimestamp(opts?.timestamp)

    this.setOwner(opts?.owner)
    this.setType(opts?.type)
    this.setTtl(opts?.ttl)
    this.setClass(opts?.class)

    for (const entry of this.constructor.rdataFields ?? []) {
      const f = RR.fieldName(entry)
      const fieldType = Array.isArray(entry) ? entry[1] : null
      const fnName = `set${this.ucFirst(f)}`
      if (typeof this[fnName] === 'function') {
        this[fnName](opts?.[f])
      } else if (fieldType) {
        this.setTypedValue(fieldType, f, opts?.[f])
      } else {
        this.set(f, opts?.[f])
      }
    }

    if (opts?.comment) this.set('comment', opts.comment)
  }

  static fromBind(line, opts = {}) {
    const instance = new this(null)
    if (opts.default !== undefined) instance.default = opts.default
    const parsed = this.parseBindLine(line)
    if (!parsed) return null
    return instance.fromBind({ ...opts, ...parsed, bindline: line })
  }

  fromBind(opts) {
    return bindFromGeneric(this, opts)
  }

  static parseBindLine(line) {
    return bindParseLine(line, RR.CLASSES)
  }

  static fromTinydns(line, opts = {}) {
    const instance = new this(null)
    if (opts.default !== undefined) instance.default = opts.default
    return instance.fromTinydns({ ...opts, tinyline: line })
  }

  fromTinydns(opts) {
    return TINYDNS.fromGeneric(this, opts)
  }

  static fromWire(wireBytes) {
    return fromWireBytes(this, wireBytes, wireUnpackDomain)
  }

  fromWire(opts) {
    return fromWireGeneric(this, opts)
  }

  static #reserved = ['__proto__', 'constructor', 'prototype']

  get(key) {
    if (RR.#reserved.includes(key)) throw new Error(`Invalid field name: ${key}`)
    return this[key]
  }

  set(key, value) {
    if (RR.#reserved.includes(key)) throw new Error(`Invalid field name: ${key}`)
    this[key] = value
    return this
  }

  toJSON() {
    const fields = [...this.getFields(), 'location', 'timestamp', 'comment']
    const obj = {}
    for (const f of fields) {
      const v = this.get(f)
      if (v !== undefined) obj[f] = v
    }
    return obj
  }

  [inspect.custom](depth, options, nextInspect) {
    // Returns a formatted string that looks like: A { ... }
    return `${this.type} ${nextInspect(this.toJSON(), options)}`
  }

  ucFirst(str) {
    if (!str) return str
    return str
      .split(/\s/)
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join('')
  }

  setClass(c) {
    if ([undefined, null, ''].includes(c)) {
      this.set('class', 'IN')
      return
    }
    if (RR.CLASSES[c.toUpperCase()]) {
      this.set('class', c.toUpperCase())
      return
    }
    this.throwHelp(`invalid class ${c}`)
  }

  setLocation(l) {
    switch (l) {
      case undefined:
        return
      default:
        this.set('location', l)
    }
  }

  setTimestamp(l) {
    switch (l) {
      case undefined:
        return
      default:
        this.set('timestamp', l)
    }
  }

  setOwner(n) {
    if (n === undefined) this.throwHelp(`owner is required`)

    if (n.length < 1 || n.length > 255)
      this.throwHelp('Domain names must have 1-255 octets (characters): RFC 2181')

    this.isFullyQualified(this.constructor.typeName ?? this.constructor.name, 'owner', n)
    this.hasValidLabels(n)

    // wildcard records: RFC 1034, 4592
    if (/\*/.test(n)) {
      if (!/^\*\./.test(n) && !/\.\*\./.test(n))
        this.throwHelp('only *.something or * (by itself) is a valid wildcard')
    }

    this.set('owner', n.toLowerCase())
  }

  setTtl(t) {
    t = t ?? this.default?.ttl
    if (t === undefined) {
      if (['SOA', 'SSHFP', 'RRSIG'].includes(this.get('type'))) return
      this.throwHelp('TTL is required, no default available')
    }

    if (typeof t !== 'number') this.throwHelp(`TTL must be numeric (${typeof t})`)

    // RFC 1035, 2181
    this.is32bitInt(this.get('type'), 'TTL', t)

    this.set('ttl', t)
  }

  setType(t) {
    if ([undefined, ''].includes(t)) t = this.constructor.typeName

    if (t === undefined) this.throwHelp(`type is required`)

    if (t.toUpperCase() !== this.constructor.typeName)
      this.throwHelp(`type ${t} doesn't match ${this.constructor.typeName}`)

    this.set('type', t.toUpperCase())
  }

  throwHelp(e) {
    if (!this.constructor.typeName) throw new Error(e)

    const typeName = this.constructor.typeName
    const example = this.getCanonical
      ? `Example ${typeName}:\n${JSON.stringify(this.getCanonical(), null, '\t')}\n\n`
      : `${typeName} records have the fields: ${this.getFields().join(', ')}\n\n`

    throw new Error(`${e}\n\n${example}${this.citeRFC()}\n`)
  }

  citeRFC() {
    return `see RFC${this.getRFCs().length > 1 ? 's' : ''} ${this.getRFCs()}`
  }

  fullyQualify(hostname, origin) {
    if (!hostname) return hostname
    if (hostname === '@' && origin) hostname = origin
    if (hostname.endsWith('.')) return hostname.toLowerCase()
    if (origin) return `${hostname}.${origin}`.toLowerCase()
    return `${hostname}.`
  }

  getPrefix(zone_opts = {}) {
    const classVal = zone_opts.hide?.class ? '' : this.get('class')

    let rrTTL = this.get('ttl')
    if (zone_opts.hide?.ttl && rrTTL === zone_opts.ttl) rrTTL = ''

    let owner = this.get('owner')
    if (zone_opts.hide?.sameOwner && zone_opts.previousOwner === owner) {
      owner = ''
    } else {
      owner = this.getFQDN('owner', zone_opts)
    }

    return `${owner}\t${rrTTL}\t${classVal}\t${this.get('type')}`
  }

  getEmpty(prop) {
    return this.get(prop) ?? ''
  }

  getComment(prop) {
    const c = this.get('comment')
    if (!c || !c[prop]) return ''
    return c[prop]
  }

  getQuoted(prop) {
    // if prop is not a quoted string field, return bare
    if (!this.isQuotedField(prop)) return this.get(prop)

    // if it's already quoted, return as-is
    if (/['"]/.test(this.get(prop)[0])) return this.get(prop)

    return `"${this.get(prop)}"` // add double quotes
  }

  static fieldName(entry) {
    return Array.isArray(entry) ? entry[0] : entry
  }

  static fieldType(entry) {
    return Array.isArray(entry) ? entry[1] : null
  }

  getRdataFields() {
    return (this.constructor.rdataFields ?? []).map((e) => RR.fieldName(e))
  }

  getTags() {
    return this.constructor.tags ?? []
  }

  getRFCs() {
    return this.constructor.RFCs ?? []
  }

  getTypeId() {
    const typeId = this.constructor.typeId
    if (typeId === undefined) this.throwHelp(`${this.constructor.typeName}: missing static typeId`)
    return typeId
  }

  static getTypeId() {
    return this.typeId
  }

  getFields(arg) {
    const commonFields = ['owner', 'ttl', 'class', 'type']
    Object.freeze(commonFields)

    const rdataFields = this.getRdataFields()

    switch (arg) {
      case 'common':
        return commonFields
      case 'rdata':
        return rdataFields
      default:
        return commonFields.concat(rdataFields)
    }
  }

  getFQDN(field, zone_opts = {}) {
    let fqdn = this.get(field)
    if (!fqdn) this.throwHelp(`empty value for field ${field}`)
    if (!fqdn.endsWith('.')) fqdn += '.'

    if (zone_opts.hide?.origin && zone_opts.origin) {
      if (fqdn === zone_opts.origin) return '@'
      if (fqdn.endsWith(zone_opts.origin)) return fqdn.slice(0, fqdn.length - zone_opts.origin.length - 1)
    }

    return fqdn
  }

  getTinyFQDN(field) {
    const val = this.get(field)
    if (val === '') return val // empty
    if (val === '.') return val // null MX

    // strip off trailing ., tinydns doesn't require it for FQDN
    if (val.endsWith('.')) return val.slice(0, -1)

    return val
  }

  getTinydnsGeneric(rdata) {
    return `:${this.getTinyFQDN('owner')}:${this.getTypeId()}:${rdata}:${this.getTinydnsPostamble()}\n`
  }

  getTinydnsPostamble() {
    return ['ttl', 'timestamp', 'location'].map((f) => this.getEmpty(f)).join(':')
  }

  hasValidLabels(hostname) {
    // RFC  952 defined valid hostnames
    // RFC 1035 limited domain label chars to letters, digits, and hyphen
    // RFC 1123 allowed hostnames to start with a digit
    // RFC 2181 'any binary string can be used as the label'
    const fq = hostname.endsWith('.') ? hostname.slice(0, -1) : hostname
    for (const label of fq.split('.')) {
      if (label.length < 1 || label.length > 63)
        this.throwHelp('Labels must have 1-63 octets (characters), RFC 2181')
    }
  }

  is8bitInt(type, field, value) {
    if (Number.isInteger(value) && value >= 0 && value <= 255) return true

    this.throwHelp(`${type} ${field} must be a 8-bit integer (in the range 0-255)`)
  }

  is16bitInt(type, field, value) {
    if (Number.isInteger(value) && value >= 0 && value <= 65535) return true

    this.throwHelp(`${type} ${field} must be a 16-bit integer (in the range 0-65535)`)
  }

  is32bitInt(type, field, value) {
    if (Number.isInteger(value) && value >= 0 && value <= 4294967295) return true

    this.throwHelp(`${type} ${field} must be a 32-bit integer (in the range 0-4294967295)`)
  }

  isBase64(type, field, value) {
    if (
      typeof value === 'string' &&
      value.length > 0 &&
      value.length % 4 === 0 &&
      /^[A-Za-z0-9+/]*={0,2}$/.test(value)
    )
      return true

    this.throwHelp(`${type} ${field} must be a valid base64 string`)
  }

  isQuoted(val) {
    return /^["']/.test(val) && /["']$/.test(val)
  }

  setFqdnValue(typeName, fieldName, val) {
    if (!val) this.throwHelp(`${typeName}: ${fieldName} is required`)
    if (this.isIPv4(val) || this.isIPv6(val))
      this.throwHelp(`${typeName}: ${fieldName} must be a domain name`)
    this.isFullyQualified(typeName, fieldName, val)
    this.isValidHostname(typeName, fieldName, val)
    this.set(fieldName, val.toLowerCase())
  }

  setTypedValue(type, fieldName, val) {
    const typeName = this.constructor.typeName
    switch (type) {
      case 'u8':
        this.is8bitInt(typeName, fieldName, val)
        this.set(fieldName, parseInt(val, 10))
        break
      case 'u16':
        this.is16bitInt(typeName, fieldName, val)
        this.set(fieldName, parseInt(val, 10))
        break
      case 'certtype': {
        if (val === undefined || val === null || val === '')
          this.throwHelp(`${typeName}: ${fieldName} is required`)
        if (typeof val === 'string' && !/^[0-9]+$/.test(val)) {
          const certTypes = this.constructor.CERT_TYPES
          if (!certTypes || !Object.hasOwn(certTypes, val)) {
            this.throwHelp(`${typeName}: unknown cert type mnemonic: ${val}`)
          }
          this.set(fieldName, val)
          break
        }
        this.is16bitInt(typeName, fieldName, val)
        this.set(fieldName, parseInt(val, 10))
        break
      }
      case 'u32':
        this.is32bitInt(typeName, fieldName, val)
        this.set(fieldName, parseInt(val, 10))
        break
      case 'fqdn':
        this.setFqdnValue(typeName, fieldName, val)
        break
      case 'base64':
        this.isBase64(typeName, fieldName, val)
        this.set(fieldName, val)
        break
      case 'hex':
        if (!/^[0-9a-fA-F]*$/.test(val)) this.throwHelp(`${typeName}: ${fieldName} must be hexadecimal`)
        this.set(fieldName, val)
        break
      case 'str':
        if (!val) this.throwHelp(`${typeName}: ${fieldName} is required`)
        this.set(fieldName, val)
        break
      case 'qstr':
        if (val === undefined || val === null) this.throwHelp(`${typeName}: ${fieldName} is required`)
        this.set(fieldName, val)
        break
      case 'charstr': {
        if (val === undefined || val === null) this.throwHelp(`${typeName}: ${fieldName} is required`)
        const value = String(val)
        const byteLen = new TextEncoder().encode(value).length
        if (byteLen > 255) this.throwHelp(`${typeName}: ${fieldName} must be <=255 bytes`)
        this.set(fieldName, value)
        break
      }
      case 'qcharstr': {
        if (val === undefined || val === null) this.throwHelp(`${typeName}: ${fieldName} is required`)
        const value = String(val)
        const byteLen = new TextEncoder().encode(value).length
        if (byteLen > 255) this.throwHelp(`${typeName}: ${fieldName} must be <=255 bytes`)
        this.set(fieldName, value)
        break
      }
      case 'charstrs':
        if (val === undefined || val === null) this.throwHelp(`${typeName}: ${fieldName} is required`)
        this.set(fieldName, val)
        break
      case 'svcparams':
        if (val === undefined || val === null) this.throwHelp(`${typeName}: ${fieldName} is required`)
        this.set(fieldName, val)
        break
      case 'ipv4':
        if (!this.isIPv4(val)) this.throwHelp(`${typeName}: ${fieldName} must be a valid IPv4 address`)
        this.set(fieldName, val)
        break
      case 'ipv6':
        if (!this.isIPv6(val)) this.throwHelp(`${typeName}: ${fieldName} must be a valid IPv6 address`)
        this.set(fieldName, this.expandIPv6(val.toLowerCase())) // lower case: RFC 5952
        break
    }
  }

  isFullyQualified(type, field, hostname) {
    if (hostname.endsWith('.')) return true

    this.throwHelp(`${type}: ${field} must be fully qualified`)
  }

  isValidHostname(type, field, hostname) {
    const allowed = new RegExp(/[^a-zA-Z0-9\-._/\\]/)
    if (!allowed.test(hostname)) return true

    const matches = allowed.exec(hostname)
    this.throwHelp(`${type}, ${field} has invalid hostname character (${matches[0]})`)
  }

  isIPv4(string) {
    // https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
    return /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/.test(string)
  }

  isIPv6(string) {
    return /^(?:(?:[a-fA-F\d]{1,4}:){7}(?:[a-fA-F\d]{1,4}|:)|(?:[a-fA-F\d]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|:[a-fA-F\d]{1,4}|:)|(?:[a-fA-F\d]{1,4}:){5}(?::(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,2}|:)|(?:[a-fA-F\d]{1,4}:){4}(?:(?::[a-fA-F\d]{1,4}){0,1}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,3}|:)|(?:[a-fA-F\d]{1,4}:){3}(?:(?::[a-fA-F\d]{1,4}){0,2}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,4}|:)|(?:[a-fA-F\d]{1,4}:){2}(?:(?::[a-fA-F\d]{1,4}){0,3}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,5}|:)|(?:[a-fA-F\d]{1,4}:){1}(?:(?::[a-fA-F\d]{1,4}){0,4}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,6}|:)|(?::(?:(?::[a-fA-F\d]{1,4}){0,5}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,7}|:)))(?:%[0-9a-zA-Z]{1,})?$/gm.test(
      string,
    )
  }

  expandIPv6(val, delimiter) {
    return TINYDNS.expandIPv6(val, delimiter)
  }

  compressIPv6(val) {
    //  * RFC 5952
    //  * 4.1. Leading zeros MUST be suppressed...A single 16-bit 0000 field MUST be represented as 0.
    //  * 4.2.1 The use of the symbol "::" MUST be used to its maximum capability.
    //  * 4.2.2 The symbol "::" MUST NOT be used to shorten just one 16-bit 0 field.
    //  * 4.2.3 When choosing placement of a "::", the longest run...MUST be shortened
    //  * 4.3 The characters a-f in an IPv6 address MUST be represented in lowercase.

    // 4.3 Lowercase and 4.1 remove leading zeros per segment
    const segments = val
      .toLowerCase()
      .split(':')
      .map((s) => s.replace(/^0+/, '') || '0')

    let bestStart = -1
    let bestLen = 0
    let curStart = -1
    let curLen = 0

    // 4.2.1 & 4.2.3 Find the longest consecutive run of '0'
    for (let i = 0; i < segments.length; i++) {
      if (segments[i] === '0') {
        if (curStart === -1) curStart = i
        curLen++
        if (curLen > bestLen) {
          bestLen = curLen
          bestStart = curStart
        }
      } else {
        curStart = -1
        curLen = 0
      }
    }

    // 4.2.2 Don't shorten a single 16-bit 0 field
    if (bestLen < 2) {
      return segments.join(':')
    }

    const head = segments.slice(0, bestStart).join(':')
    const tail = segments.slice(bestStart + bestLen).join(':')

    return `${head}::${tail}`
  }

  octalToUint8Array(octalStr) {
    const str = TINYDNS.octalToChar(octalStr)
    return Uint8Array.from(str, (c) => c.charCodeAt(0))
  }

  wireUnpackDomain(bytes, offset = 0) {
    return wireUnpackDomain(bytes, offset)
  }

  wirePackDomain(fqdn) {
    return wirePackDomain(fqdn)
  }

  getWireRdata() {
    return wireGetRdata(this)
  }

  toWire() {
    return wireToWire(this, RR.CLASSES)
  }

  toBind(zone_opts) {
    return bindToGeneric(this, zone_opts)
  }

  parseTinydnsLine(tinyline) {
    const parsed = TINYDNS.parseGenericLine(tinyline)
    return { ...parsed, owner: this.fullyQualify(parsed.owner) }
  }

  toTinydns() {
    return TINYDNS.to(this)
  }

  isFqdnField(field) {
    return (
      (this.constructor.rdataFields ?? []).some(
        (entry) => RR.fieldName(entry) === field && RR.fieldType(entry) === 'fqdn',
      ) || false
    )
  }

  isQuotedField(field) {
    const quotedTypes = new Set(['qstr', 'qcharstr', 'charstrs'])
    return (
      (this.constructor.rdataFields ?? []).some(
        (entry) => RR.fieldName(entry) === field && quotedTypes.has(RR.fieldType(entry)),
      ) || false
    )
  }

  toMaraDNS() {
    const type = this.get('type')
    const supportedTypes = 'A PTR MX AAAA SRV NAPTR NS SOA TXT SPF RAW FQDN4 FQDN6 CNAME HINFO WKS LOC'.split(
      /\s+/g,
    )
    if (!supportedTypes.includes(type)) return this.toMaraGeneric()
    return `${this.get('owner')}\t+${this.get('ttl')}\t${type}\t${this.getFields('rdata')
      .map((f) => this.getQuoted(f))
      .join('\t')} ~\n`
  }

  toMaraGeneric() {
    // this.throwHelp(`\nMaraDNS does not support ${type} records yet and this package does not support MaraDNS generic records. Yet.\n`)
    return `${this.get('owner')}\t+${this.get('ttl')}\tRAW ${this.getTypeId()}\t'${this.getFields('rdata')
      .map((f) => this.getQuoted(f))
      .join(' ')}' ~\n`
  }
}
