import * as TINYDNS from './lib/tinydns.js'
import { lowercaseName, nameToLabels } from './lib/name.js'
import * as MARADNS from './lib/maradns.js'
import { canonicalTypeList, typeNameToId } from './lib/binary.js'

const customInspect = Symbol.for('nodejs.util.inspect.custom')
import {
  wireUnpackDomain,
  wirePackDomain,
  toWire as wireToWire,
  fromWireBytes,
  fromWireGeneric,
  ipv6Bytes,
  ipv6ToPresentation,
  toWireGeneric,
  mandatoryKeyIds,
  parseSvcParams,
  svcParamKeyName,
  svcParamsFromWire,
  svcParamsToWire,
} from './lib/wire.js'
import {
  parseBindLine as bindParseLine,
  assertType as bindAssertType,
  fromBind as bindFromGeneric,
  fromBind3597 as bindFrom3597,
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
    parsed.ttl ??= opts.default?.ttl
    if (parsed.rdata[0]?.text === '\\#' && !parsed.rdata[0].quoted) return bindFrom3597(instance, parsed) // RFC 3597 §5
    bindAssertType(parsed.type, this)
    return instance.fromBind({ ...opts, ...parsed })
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
    if (this.constructor.tinydnsType) return TINYDNS.fromGeneric(this, opts)
    return this.fromTinydnsWire(opts)
  }

  // A generic `:` line is the type number and the wire rdata, octal-escaped.
  fromTinydnsWire({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline)
    if (Number(typeId) !== this.getTypeId())
      this.throwHelp(`${this.constructor.typeName} fromTinydns: type ${typeId} is not ${this.getTypeId()}`)
    const rr = this.fromWire({
      owner,
      cls: 'IN',
      ttl,
      rdata: TINYDNS.octalRdataToBytes(rdata ?? ''),
      typeId: Number(typeId),
    })
    rr.setTimestamp(timestamp)
    rr.setLocation(location)
    return rr
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

  [customInspect](depth, options, nextInspect) {
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
    if (typeof c !== 'string') this.throwHelp(`invalid class ${c}`)
    if (RR.CLASSES[c.toUpperCase()]) {
      this.set('class', c.toUpperCase())
      return
    }
    const generic = c.toUpperCase().match(/^CLASS(\d+)$/) // RFC 3597 §5
    if (generic && parseInt(generic[1], 10) <= 65535) {
      const id = parseInt(generic[1], 10)
      const known = Object.keys(RR.CLASSES).find((k) => RR.CLASSES[k] === id)
      this.set('class', known ?? `CLASS${id}`)
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
    if (n === undefined || n === '') this.throwHelp(`owner is required`)

    const typeName = this.constructor.typeName ?? this.constructor.name
    this.isFullyQualified(typeName, 'owner', n)
    this.isValidName(typeName, 'owner', n)

    // RFC 4592: a wildcard is a leftmost label of exactly `*`. An escaped \* or
    // \042 is a literal byte and may appear anywhere.
    const unescaped = n.replace(/\\(?:[0-9]{3}|.)/g, '_')
    if (unescaped.split('.').some((label, i) => label.includes('*') && (label !== '*' || i > 0)))
      this.throwHelp('only *.something or * (by itself) is a valid wildcard')

    this.set('owner', lowercaseName(n))
  }

  setTtl(t) {
    t = t ?? this.default?.ttl
    if (t === undefined) {
      if (['SOA', 'SSHFP', 'RRSIG'].includes(this.get('type'))) return
      this.throwHelp('TTL is required, no default available')
    }

    if (typeof t !== 'number') this.throwHelp(`TTL must be numeric (${typeof t})`)

    // RFC 2181 §8: the high bit is reserved, so a TTL is 0 to 2^31 - 1.
    if (!Number.isInteger(t) || t < 0 || t > 2147483647)
      this.throwHelp(`TTL must be an integer from 0 to 2147483647 (RFC 2181 §8)`)

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
    if (hostname.endsWith('.')) return lowercaseName(hostname)
    if (origin) return lowercaseName(`${hostname}.${origin}`)
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
    if (!this.isQuotedField(prop)) return this.get(prop)
    return MARADNS.quoteCharString(this.get(prop))
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

  getClassId() {
    const c = this.get('class')
    return RR.CLASSES[c] ?? parseInt(c.slice(5), 10) // 'CLASS32' -> 32
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
    // every tinydns line ends with this, making it the choke point for the
    // class guard: tinydns data files have no class field
    this.assertClassIN('tinydns')
    return ['ttl', 'timestamp', 'location'].map((f) => this.getEmpty(f)).join(':')
  }

  assertClassIN(format) {
    if (this.get('class') !== 'IN')
      this.throwHelp(`${format} supports only class IN, got ${this.get('class')}`)
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

  // RFC 4034 §3.2: a signature time is epoch seconds or YYYYMMDDHHmmSS in UTC.
  // Fourteen digits always exceed 32 bits, so the two forms cannot collide.
  setSignatureTime(field, val) {
    const date = String(val).match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/)
    if (date) {
      const ms = Date.UTC(date[1], date[2] - 1, date[3], date[4], date[5], date[6])
      if (formatSignatureTime(ms / 1000) !== date[0])
        this.throwHelp(`${this.constructor.typeName} ${field} is not a valid date: ${val}`)
      // modulo 2^32, so a date before 1970 wraps into the unsigned range
      val = (((ms / 1000) % 2 ** 32) + 2 ** 32) % 2 ** 32
    }
    this.is32bitInt(this.constructor.typeName, field, val)
    this.set(field, val)
  }

  // Hex octets, of an exact length when the field's algorithm fixes one. Stored
  // uppercase, as the wire decoder and BIND write them.
  isHexDigest(field, value, bytes) {
    const typeName = this.constructor.typeName
    if (typeof value !== 'string' || !/^([0-9a-fA-F]{2})+$/.test(value))
      this.throwHelp(`${typeName}: ${field} must be hex octets`)
    if (bytes !== undefined && value.length !== bytes * 2)
      this.throwHelp(`${typeName}: ${field} must be ${bytes} bytes, got ${value.length / 2}`)
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

  isFqdnValue(typeName, fieldName, val) {
    if (!val) this.throwHelp(`${typeName}: ${fieldName} is required`)
    if (this.isIPv4(val) || this.isIPv6(val))
      this.throwHelp(`${typeName}: ${fieldName} must be a domain name`)
    this.isFullyQualified(typeName, fieldName, val)
    this.isValidName(typeName, fieldName, val)
  }

  setFqdnValue(typeName, fieldName, val) {
    this.isFqdnValue(typeName, fieldName, val)
    this.set(fieldName, lowercaseName(val))
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
      case 'rrtype':
        try {
          this.set(fieldName, typeNameToId(val))
        } catch {
          this.throwHelp(`${typeName}: ${fieldName} is not a type name, TYPEnnn, or 0-65535`)
        }
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
        this.set(fieldName, val.toUpperCase())
        break
      case 'str':
        if (!val) this.throwHelp(`${typeName}: ${fieldName} is required`)
        this.set(fieldName, val)
        break
      case 'qstr':
        if (val === undefined || val === null) this.throwHelp(`${typeName}: ${fieldName} is required`)
        this.set(fieldName, val)
        break
      case 'charstr':
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
        this.setSvcParams(fieldName, val ?? '')
        break
      case 'list':
        this.set(fieldName, val ?? '')
        break
      case 'ipv4':
        if (!this.isIPv4(val)) this.throwHelp(`${typeName}: ${fieldName} must be a valid IPv4 address`)
        this.set(fieldName, val)
        break
      case 'ipv6':
        if (!this.isIPv6(val)) this.throwHelp(`${typeName}: ${fieldName} must be a valid IPv6 address`)
        this.set(fieldName, this.expandIPv6(val.toLowerCase())) // lower case: RFC 5952
        break
      default:
        throw new Error(`${typeName}: unknown rdata field type ${type} for ${fieldName}`)
    }
  }

  // Stored in ascending type order, so equal type sets compare equal.
  setTypeList(fieldName, val) {
    try {
      this.set(fieldName, canonicalTypeList(val))
    } catch (e) {
      this.throwHelp(`${this.constructor.typeName}: ${fieldName}: ${e.message}`)
    }
  }

  setSvcParams(fieldName, val) {
    const typeName = this.constructor.typeName
    let params
    try {
      params = parseSvcParams(val)
    } catch (e) {
      this.throwHelp(`${typeName}: ${e.message.replace(/^SVCB: /, '')}`)
    }
    // RFC 9460 §2.4.2: BIND rejects params in AliasMode.
    if (this.get('priority') === 0 && params.size)
      this.throwHelp(`${typeName}: AliasMode (priority 0) takes no params`)
    // RFC 9460 §7.1.1
    if (params.has(2) && !params.has(1)) this.throwHelp(`${typeName}: no-default-alpn requires alpn`)
    // RFC 9460 §8: every mandatory key must be present.
    const missing = mandatoryKeyIds(params.get(0) ?? []).filter((id) => !params.has(id))
    if (missing.length)
      this.throwHelp(`${typeName}: mandatory keys missing: ${missing.map(svcParamKeyName).join(', ')}`)
    // Stored in the form the wire decodes to, so equal params compare equal.
    this.set(fieldName, svcParamsFromWire(svcParamsToWire(val)))
  }

  lowercaseName(name) {
    return lowercaseName(name)
  }

  isFullyQualified(type, field, hostname) {
    if (hostname.endsWith('.')) return true

    this.throwHelp(`${type}: ${field} must be fully qualified`)
  }

  // RFC 2181 §11: any binary string can be a label, 1-63 octets, and the
  // name 255 octets on the wire, length octets and root included.
  isValidName(type, field, hostname) {
    let labels
    try {
      labels = nameToLabels(hostname)
    } catch (e) {
      this.throwHelp(`${e.message}, RFC 2181`)
    }
    const wireLength = labels.reduce((n, label) => n + 1 + label.length, 1)
    if (wireLength > 255) this.throwHelp(`Domain names must have 1-255 octets, got ${wireLength}: RFC 2181`)
    // Names are stored in presentation form, so master-file delimiters and
    // controls must arrive escaped (\032, \;, \000) or the BIND export breaks.
    if (/[\s;"()\p{Cc}]/u.test(hostname.replace(/\\(?:[0-9]{3}|.)/g, '_')))
      this.throwHelp(`${type}: ${field} has an unescaped delimiter or control: ${hostname}`)
    return true
  }

  isIPv4(string) {
    // https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
    return /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/.test(string)
  }

  isIPv6(string) {
    try {
      ipv6Bytes(string)
      return true
    } catch {
      return false
    }
  }

  // all eight groups, four lowercase digits each (RFC 5952 §4.3)
  expandIPv6(val, delimiter = ':') {
    return ipv6ToPresentation(ipv6Bytes(val)).replaceAll(':', delimiter)
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

  wireUnpackDomain(bytes, offset = 0) {
    return wireUnpackDomain(bytes, offset)
  }

  wirePackDomain(fqdn) {
    return wirePackDomain(fqdn)
  }

  getWireRdata() {
    return toWireGeneric(this)
  }

  toWire() {
    return wireToWire(this)
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
    // MaraDNS csv2 zone files have no class field either
    this.assertClassIN('MaraDNS')
    const type = this.get('type')
    const supportedTypes = 'A PTR MX AAAA SRV NAPTR NS SOA TXT SPF RAW FQDN4 FQDN6 CNAME HINFO WKS LOC'.split(
      /\s+/g,
    )
    if (!supportedTypes.includes(type)) return this.toMaraGeneric()
    // csv2's MX and NAPTR parsers reject a bare '.' (the root) as a name.
    const fields = this.getFields('rdata')
    if (fields.some((f) => this.isFqdnField(f) && this.get(f) === '.')) return this.toMaraGeneric()
    // csv2 separates adjacent character-strings with ';' (HINFO, NAPTR).
    const rdata = fields
      .map((f, i) => {
        const sep = i === 0 ? '' : this.isQuotedField(f) && this.isQuotedField(fields[i - 1]) ? ';' : '\t'
        return sep + this.getQuoted(f)
      })
      .join('')
    return `${this.get('owner')}\t+${this.get('ttl')}\t${type}\t${rdata} ~\n`
  }

  toMaraGeneric() {
    this.assertClassIN('MaraDNS')
    // csv2 refuses these types even as RAW.
    if (['A6', 'DNAME', 'OPT'].includes(this.get('type')))
      this.throwHelp(`MaraDNS does not support ${this.get('type')} records`)
    // MaraDNS csv2 interprets \xNN escapes only outside quoted text, so every
    // rdata byte is emitted as an unquoted escape. '' is zero-length rdata.
    const bytes = this.getWireRdata()
    const rdata = bytes.length
      ? [...bytes].map((b) => `\\x${b.toString(16).padStart(2, '0')}`).join('')
      : `''`
    return `${this.get('owner')}\t+${this.get('ttl')}\tRAW ${this.getTypeId()}\t${rdata} ~\n`
  }
}

export function formatSignatureTime(seconds) {
  return new Date(seconds * 1000).toISOString().replace(/\D/g, '').slice(0, 14)
}
