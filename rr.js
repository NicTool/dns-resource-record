import * as TINYDNS from './lib/tinydns.js'

export default class RR extends Map {
  constructor(opts) {
    super()

    if (opts === null) return

    if (opts?.default) this.default = opts.default

    if (opts?.bindline) return this.fromBind(opts)
    if (opts?.tinyline) return this.fromTinydns(opts)

    // tinydns specific
    this.setLocation(opts?.location)
    this.setTimestamp(opts?.timestamp)

    this.setOwner(opts?.owner)
    this.setType(opts?.type)
    this.setTtl(opts?.ttl)
    this.setClass(opts?.class)

    for (const f of this.getFields('rdata')) {
      const fnName = `set${this.ucFirst(f)}`
      if (this[fnName] === undefined) this.throwHelp(`Missing ${fnName} in class ${this.get('type')}`)
      this[fnName](opts?.[f])
    }

    if (opts?.comment) this.set('comment', opts.comment)
  }

  ucFirst(str) {
    return str
      .split(/\s/)
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join('')
  }

  setClass(c) {
    switch (c) {
      case 'IN': // 1
      case undefined:
      case null:
      case '':
        this.set('class', 'IN')
        break
      case 'CS': // 2
      case 'CH': // 3
      case 'HS': // 4
      case 'NONE': // 254
      case 'ANY': // 255
        this.set('class', c)
        break
      default:
        this.throwHelp(`invalid class ${c}`)
    }
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

    this.isFullyQualified(this.constructor.name, 'owner', n)
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
      if (['SOA', 'SSHPF'].includes(this.get('type'))) return
      this.throwHelp('TTL is required, no default available')
    }

    if (typeof t !== 'number') this.throwHelp(`TTL must be numeric (${typeof t})`)

    // RFC 1035, 2181
    this.is32bitInt(this.get('type'), 'TTL', t)

    this.set('ttl', t)
  }

  setType(t) {
    switch (t) {
      case '':
      case undefined:
        this.throwHelp(`type is required`)
    }

    if (t.toUpperCase() !== this.constructor.name)
      this.throwHelp(`type ${t} doesn't match ${this.constructor.name}`)

    this.set('type', t.toUpperCase())
  }

  throwHelp(e) {
    if (this.constructor.name === 'RR') throw new Error(e)

    const example = this.getCanonical
      ? `Example ${this.constructor.name}:\n${JSON.stringify(this.getCanonical(), null, '\t')}\n\n`
      : `${this.constructor.name} records have the fields: ${this.getFields().join(', ')}\n\n`

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
    // if prop is not in quoted list, return bare
    if (!this.getQuotedFields().includes(prop)) return this.get(prop)

    // if it's already quoted, return as-is
    if (/['"]/.test(this.get(prop)[0])) return this.get(prop)

    return `"${this.get(prop)}"` // add double quotes
  }

  getQuotedFields() {
    return []
  }

  getRdataFields() {
    return []
  }

  getTags() {
    return []
  }

  getFields(arg) {
    const commonFields = ['owner', 'ttl', 'class', 'type']
    Object.freeze(commonFields)

    switch (arg) {
      case 'common':
        return commonFields
      case 'rdata':
        return this.getRdataFields()
      default:
        return commonFields.concat(this.getRdataFields())
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
    if (
      typeof value === 'number' &&
      parseInt(value, 10) === value && // assure integer
      value >= 0 &&
      value <= 255
    )
      return true

    this.throwHelp(`${type} ${field} must be a 8-bit integer (in the range 0-255)`)
  }

  is16bitInt(type, field, value) {
    if (
      typeof value === 'number' &&
      parseInt(value, 10) === value && // assure integer
      value >= 0 &&
      value <= 65535
    )
      return true

    this.throwHelp(`${type} ${field} must be a 16-bit integer (in the range 0-65535)`)
  }

  is32bitInt(type, field, value) {
    if (
      typeof value === 'number' &&
      parseInt(value, 10) === value && // assure integer
      value >= 0 &&
      value <= 2147483647
    )
      return true

    this.throwHelp(`${type} ${field} must be a 32-bit integer (in the range 0-2147483647)`)
  }

  isQuoted(val) {
    return /^["']/.test(val) && /["']$/.test(val)
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

  octalToBuffer(octalStr) {
    return Buffer.from(TINYDNS.octalToChar(octalStr), 'binary')
  }

  wirePackDomain(fqdn) {
    return packDomainNameWire(fqdn)
  }

  getWireRdata() {
    const line = this.toTinydns()
    if (!line.startsWith(':'))
      throw new Error(`${this.get('type')}: override getWireRdata() — non-generic tinydns format`)
    // line: :fqdn:typeId:rdata:ttl:ts:loc\n
    const rdata = line.split(':')[3]
    return this.octalToBuffer(rdata ?? '')
  }

  toWire() {
    const rdata = this.getWireRdata()
    const owner = this.wirePackDomain(this.get('owner'))
    const classMap = { IN: 1, CS: 2, CH: 3, HS: 4, NONE: 254, ANY: 255 }
    const meta = Buffer.alloc(10)
    meta.writeUInt16BE(this.getTypeId(), 0)
    meta.writeUInt16BE(classMap[this.get('class')] ?? 1, 2)
    meta.writeUInt32BE(this.get('ttl'), 4)
    meta.writeUInt16BE(rdata.length, 8)
    return Buffer.concat([owner, meta, rdata])
  }

  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.getRdataFields()
      .map((f) => this.getQuoted(f))
      .join('\t')}\n`
  }

  toMaraDNS() {
    const type = this.get('type')
    const supportedTypes = 'A PTR MX AAAA SRV NAPTR NS SOA TXT SPF RAW FQDN4 FQDN6 CNAME HINFO WKS LOC'.split(
      /\s+/g,
    )
    if (!supportedTypes.includes(type)) return this.toMaraGeneric()
    return `${this.get('owner')}\t+${this.get('ttl')}\t${type}\t${this.getRdataFields()
      .map((f) => this.getQuoted(f))
      .join('\t')} ~\n`
  }

  toMaraGeneric() {
    // this.throwHelp(`\nMaraDNS does not support ${type} records yet and this package does not support MaraDNS generic records. Yet.\n`)
    return `${this.get('owner')}\t+${this.get('ttl')}\tRAW ${this.getTypeId()}\t'${this.getRdataFields()
      .map((f) => this.getQuoted(f))
      .join(' ')}' ~\n`
  }
}

function packDomainNameWire(fqdn) {
  if (fqdn === '.') return Buffer.from([0])
  const parts = fqdn.split('.')
  let len = 0
  for (const part of parts) {
    if (part.length > 0) len += part.length + 1
  }
  len += 1 // for the final \0

  const buf = Buffer.allocUnsafe(len)
  let offset = 0
  for (const part of parts) {
    if (part.length > 0) {
      buf.writeUInt8(part.length, offset++)
      buf.write(part, offset, 'ascii')
      offset += part.length
    }
  }
  buf.writeUInt8(0, offset)
  return buf
}
