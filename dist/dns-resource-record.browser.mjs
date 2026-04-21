const octalRe = new RegExp(/\\(?:[1-7][0-7]{0,2}|[0-7]{2,3})/, 'g')

function escapeOctal(re, str) {
  let escaped = ''
  str.split(/(.{1})/g).map((c) => {
    escaped += re.test(c) ? charToOctal(c) : c
  })
  return escaped
}

function unescapeOctal(str) {
  return this.octalToChar(str)
}

function octalToChar(str) {
  // relace instances of \NNN with ASCII
  return str.replace(octalRe, (o) => String.fromCharCode(parseInt(o.slice(1), 8)))
}

function octalToHex(str) {
  // relace instances of \NNN with Hex
  return str.replace(octalRe, (o) => {
    // parseInt(n, 8) -> from octal to decimal
    //  .toString(16) -> decimal to hex
    return parseInt(o.slice(1), 8).toString(16).padStart(2, 0)
  })
}

function octalToUInt8(str) {
  const b = Buffer.alloc(1)
  b.writeUInt8(parseInt(str.slice(1, 4), 8), 0)
  return b.readUInt8()
}

function octalToUInt16(str) {
  const b = Buffer.alloc(2)
  b.writeUInt8(parseInt(str.slice(1, 4), 8), 0)
  b.writeUInt8(parseInt(str.slice(5, 8), 8), 1)
  return b.readUInt16BE()
}

function octalToUInt32(str) {
  const b = Buffer.alloc(4)
  b.writeUInt8(parseInt(str.slice(1, 4), 8), 0)
  b.writeUInt8(parseInt(str.slice(5, 8), 8), 1)
  b.writeUInt8(parseInt(str.slice(9, 12), 8), 2)
  b.writeUInt8(parseInt(str.slice(13, 16), 8), 3)
  return b.readUInt32BE()
}

function packString(str) {
  return str
    .match(/(.{1,255})/g)
    .map((s) => {
      const len = Buffer.alloc(1)
      len.writeUInt8(s.length)
      return `${UInt8toOctal(len.readUInt8(0))}${s}`
    })
    .join('')
}

function unpackString(str) {
  const asBuf = Buffer.from(octalToChar(str.toString()))
  const res = []
  let pos = 0
  let len
  while ((len = asBuf.readUInt8(pos))) {
    // encoded length byte
    pos++
    res.push(asBuf.slice(pos, pos + len).toString())
    pos = +(pos + len)
    if (pos >= asBuf.length) break
  }
  return res
}

function packDomainName(fqdn) {
  const labelRegEx = new RegExp(/[^A-Za-z0-9-.]/, 'g')

  // RFC 1035, 3.3 Standard RRs
  // The standard wire format for DNS names. (1 octet length + octets)
  let packed = ''
  fqdn.split('.').forEach((label) => {
    if (label === undefined || !label.length) return

    const len = Buffer.alloc(1)
    len.writeUInt8(label.length)
    packed += UInt8toOctal(len.readUInt8(0))

    packed += escapeOctal(labelRegEx, label)
  })
  packed += '\\000' // terminates with a zero length label
  return packed
}

function unpackDomainName(escaped) {
  let pos = 0
  let binaryLen = 0
  const labels = []

  // consume the next logical "byte" (char or octal escape)
  const getNextByte = () => {
    if (pos >= escaped.length) return null

    let value
    if (escaped[pos] === '\\') {
      value = parseInt(escaped.slice(pos + 1, pos + 4), 8)
      pos += 4
    } else {
      value = escaped.charCodeAt(pos++)
    }

    binaryLen++
    return value
  }

  let lengthByte
  while ((lengthByte = getNextByte()) && lengthByte !== 0) {
    let label = ''
    for (let i = 0; i < lengthByte; i++) {
      const char = getNextByte()
      if (char === null) break
      label += String.fromCharCode(char)
    }
    labels.push(label)
  }

  return [`${labels.join('.')}.`, pos, binaryLen]
}

function packHex(str) {
  let r = ''
  for (let i = 0; i < str.length; i = i + 2) {
    // nibble off 2 hex bytes, encode to octal
    r += UInt8toOctal(parseInt(str.slice(i, i + 2), 16))
  }
  return r
}

function charToOctal(c) {
  if (typeof c === 'number') return UInt8toOctal(c)

  return UInt8toOctal(c.charCodeAt(0))
}

function UInt8toOctal(n) {
  if (n > 255) throw new Error('UInt8toOctal does not work on numbers > 255')

  return `\\${parseInt(n, 10).toString(8).padStart(3, 0)}`
}

function UInt16toOctal(n) {
  let r = ''
  const pri = Buffer.alloc(2)
  pri.writeUInt16BE(n)
  r += UInt8toOctal(pri.readUInt8(0))
  r += UInt8toOctal(pri.readUInt8(1))
  return r
}

function UInt32toOctal(n) {
  let r = ''
  const pri = Buffer.alloc(4)
  pri.writeUInt32BE(n)
  for (let i = 0; i < 4; i++) {
    r += UInt8toOctal(pri.readUInt8(i))
  }
  return r
}

function ipv4toOctal(ip) {
  return UInt32toOctal(ip.split`.`.reduce((int, value) => int * 256 + +value))
}

function octalToIPv4(str) {
  const asInt = octalToUInt32(str)
  return [24, 16, 8, 0].map((n) => (asInt >> n) & 0xff).join('.')
}

function ipv6toOctal(ip) {
  return packHex(ip.replace(/:/g, ''))
}

function octalToIPv6(str) {
  return octalToHex(str)
    .match(/(.{4})/g)
    .join(':')
}

function base64toOctal(str) {
  const bytes = Buffer.from(str, 'base64')
  let escaped = ''
  for (const b of bytes) {
    escaped += /[A-Za-z0-9\-.]/.test(String.fromCharCode(b)) ? String.fromCharCode(b) : UInt8toOctal(b)
  }
  return escaped
}

function octalToBase64(str) {
  return Buffer.from(octalToChar(str), 'binary').toString('base64')
}

class RR extends Map {
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
    const str = octalToChar(octalStr)
    return Uint8Array.from(str, (c) => c.charCodeAt(0))
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
    const result = new Uint8Array(owner.length + 10 + rdata.length)
    result.set(owner, 0)
    const meta = new DataView(result.buffer, owner.length, 10)
    meta.setUint16(0, this.getTypeId())
    meta.setUint16(2, classMap[this.get('class')] ?? 1)
    meta.setUint32(4, this.get('ttl'))
    meta.setUint16(8, rdata.length)
    result.set(rdata, owner.length + 10)
    return result
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
  if (fqdn === '.') return new Uint8Array([0])
  const enc = new TextEncoder()
  const parts = fqdn.split('.')
  let len = 0
  for (const part of parts) {
    if (part.length > 0) len += part.length + 1
  }
  len += 1 // for the final \0

  const buf = new Uint8Array(len)
  let offset = 0
  for (const part of parts) {
    if (part.length > 0) {
      buf[offset++] = part.length
      buf.set(enc.encode(part), offset)
      offset += part.length
    }
  }
  buf[offset] = 0
  return buf
}

class A extends RR {
  static typeName = 'A'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('A: address is required')
    if (!this.isIPv4(val)) this.throwHelp('A address must be IPv4')
    this.set('address', val)
  }

  getDescription() {
    return 'Address'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['address']
  }

  getRFCs() {
    return [1035]
  }

  getTypeId() {
    return 1
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      class: 'IN',
      ttl: 3600,
      type: 'A',
      address: '192.0.2.127',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // +fqdn:ip:ttl:timestamp:lo
    const [owner, ip, ttl, ts, loc] = tinyline.slice(1).split(':')

    return new A({
      owner: this.fullyQualify(owner),
      type: 'A',
      address: ip,
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  A  192.0.2.127
    const [owner, ttl, c, type, address] = bindline.split(/\s+/)
    return new A({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      address,
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return new Uint8Array(this.get('address').split('.').map(Number))
  }

  toTinydns() {
    return `+${this.getTinyFQDN('owner')}:${this.get('address')}:${this.getTinydnsPostamble()}\n`
  }
}

class AAAA extends RR {
  static typeName = 'AAAA'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('AAAA: address is required')
    if (!this.isIPv6(val)) this.throwHelp(`AAAA: address must be IPv6 (${val})`)

    this.set('address', this.expand(val.toLowerCase())) // lower case: RFC 5952
  }

  getCompressed(val) {
    return this.compress(val ?? this.get('address'))
  }

  getDescription() {
    return 'Address IPv6'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['address']
  }

  getRFCs() {
    return [3596, 5952]
  }

  getTypeId() {
    return 28
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      address: '2001:0db8:0020:000a:0000:0000:0000:0004',
      class: 'IN',
      ttl: 3600,
      type: 'AAAA',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    const str = tinyline
    let fqdn, ip, n, rdata, ttl, ts, loc

    switch (str[0]) {
      case ':':
        ;[fqdn, n, rdata, ttl, ts, loc] = str.slice(1).split(':')
        if (n != 28) this.throwHelp('AAAA fromTinydns, invalid n')
        ip = octalToHex(rdata)
          .match(/([0-9a-fA-F]{4})/g)
          .join(':')
        break
      case '3':
      case '6':
        ;[fqdn, rdata, ttl, ts, loc] = str.slice(1).split(':')
        ip = rdata.match(/(.{4})/g).join(':')
        break
    }

    return new AAAA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'AAAA',
      address: ip,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  AAAA  ...
    const [owner, ttl, c, type, ip] = bindline.split(/\s+/)
    return new AAAA({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      address: this.expand(ip),
    })
  }

  compress(val) {
    /*
     * RFC 5952
     * 4.1. Leading zeros MUST be suppressed...A single 16-bit 0000 field MUST be represented as 0.
     * 4.2.1 The use of the symbol "::" MUST be used to its maximum capability.
     * 4.2.2 The symbol "::" MUST NOT be used to shorten just one 16-bit 0 field.
     * 4.2.3 When choosing placement of a "::", the longest run...MUST be shortened
     * 4.3 The characters a-f in an IPv6 address MUST be represented in lowercase.
     */
    let r = val
      .replace(/0000/g, '0') // 4.1 0000 -> 0
      .replace(/:0+([1-9a-fA-F])/g, ':$1') // 4.1 remove leading zeros

    const mostConsecutiveZeros = [
      new RegExp(/0?(?::0){6,}:0?/),
      new RegExp(/0?(?::0){5,}:0?/),
      new RegExp(/0?(?::0){4,}:0?/),
      new RegExp(/0?(?::0){3,}:0?/),
      new RegExp(/0?(?::0){2,}:0?/),
    ]

    for (const re of mostConsecutiveZeros) {
      if (re.test(r)) {
        r = r.replace(re, '::') // 4.2
        break
      }
    }

    return r.toLowerCase() // 4.3
  }

  expand(val, delimiter) {
    if (delimiter === undefined) delimiter = ':'

    const colons = val.match(/:/g)
    if (colons?.length < 7) {
      // console.log(`AAAA: restoring compressed colons`)
      val = val.replace(/::/, ':'.repeat(9 - colons.length))
    }

    // restore compressed leading zeros
    return val
      .split(':')
      .map((s) => s.padStart(4, 0))
      .join(delimiter)
      .toLowerCase()
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    const hex = this.expand(this.get('address'), '')
    const arr = new Uint8Array(hex.length / 2)
    for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    return arr
  }

  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.getCompressed()}\n`
  }

  toTinydns() {
    // from AAAA notation (8 groups of 4 hex digits) to 16 escaped octals
    const rdata = packHex(this.expand(this.get('address'), ''))
    return this.getTinydnsGeneric(rdata)
  }
}

class APL extends RR {
  static typeName = 'APL'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAplRdata(val) {
    if (!val) this.throwHelp('APL: apl rdata is required')
    // apl rdata is a list of address prefix list items, e.g.:
    // 1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::/32
    this.set('apl rdata', val)
  }

  getDescription() {
    return 'Address Prefix List'
  }

  getRdataFields(arg) {
    return ['apl rdata']
  }

  getRFCs() {
    return [3123]
  }

  getTypeId() {
    return 42
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'APL',
      'apl rdata': '1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::/32',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // APL via generic, :fqdn:42:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 42) this.throwHelp('APL fromTinydns, invalid n')

    const bytes = Buffer.from(octalToChar(rdata), 'binary')
    const items = []
    let pos = 0

    while (pos < bytes.length) {
      const afi = bytes.readUInt16BE(pos)
      pos += 2
      const prefix = bytes.readUInt8(pos)
      pos++
      const adfLenByte = bytes.readUInt8(pos)
      pos++
      const neg = (adfLenByte & 0x80) !== 0
      const addrLen = adfLenByte & 0x7f
      const addrBytes = bytes.slice(pos, pos + addrLen)
      pos += addrLen

      let addr
      if (afi === 1) {
        const padded = Buffer.alloc(4)
        addrBytes.copy(padded)
        addr = [...padded].join('.')
      } else {
        const padded = Buffer.alloc(16)
        addrBytes.copy(padded)
        const groups = []
        for (let i = 0; i < 16; i += 2) groups.push(padded.readUInt16BE(i).toString(16).padStart(4, '0'))
        addr = this.compressIPv6(groups.join(':'))
      }

      items.push(`${neg ? '!' : ''}${afi}:${addr}/${prefix}`)
    }

    return new APL({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'APL',
      'apl rdata': items.join(' '),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  APL  {[!]afi:address/prefix}*
    const parts = bindline.split(/\s+/)
    const [owner, ttl, c, type] = parts
    return new APL({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      'apl rdata': parts.slice(4).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      this.get('apl rdata')
        .split(/\s+/)
        .map((item) => {
          const neg = item.startsWith('!')
          const bare = neg ? item.slice(1) : item
          const colonIdx = bare.indexOf(':')
          const afi = parseInt(bare.slice(0, colonIdx), 10)
          const rest = bare.slice(colonIdx + 1)
          const slashIdx = rest.lastIndexOf('/')
          const addr = rest.slice(0, slashIdx)
          const prefix = parseInt(rest.slice(slashIdx + 1), 10)

          let addrBytes
          if (afi === 1) {
            addrBytes = Buffer.from(addr.split('.').map((n) => parseInt(n, 10)))
          } else {
            const dblIdx = addr.indexOf('::')
            let groups
            if (dblIdx !== -1) {
              const left = addr
                .slice(0, dblIdx)
                .split(':')
                .filter((s) => s !== '')
              const right = addr
                .slice(dblIdx + 2)
                .split(':')
                .filter((s) => s !== '')
              groups = [...left, ...Array(8 - left.length - right.length).fill('0000'), ...right]
            } else {
              groups = addr.split(':')
            }
            addrBytes = Buffer.from(groups.map((g) => g.padStart(4, '0')).join(''), 'hex')
          }

          let len = addrBytes.length
          while (len > 0 && addrBytes[len - 1] === 0) len--
          const afdPart = addrBytes.slice(0, len)

          let r = UInt16toOctal(afi)
          r += UInt8toOctal(prefix)
          r += UInt8toOctal((neg ? 0x80 : 0) | afdPart.length)
          for (const b of afdPart) r += UInt8toOctal(b)
          return r
        })
        .join(''),
    )
  }
}

class CAA extends RR {
  static typeName = 'CAA'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags(val) {
    this.is8bitInt('CAA', 'flags', val)

    if (!this.getFlagsOptions().has(val)) {
      this.throwHelp(`CAA flags ${val} not recognized`)
    }

    this.set('flags', val)
  }

  getFlagsOptions() {
    return new Map([
      [0, 'Non Critical'],
      [128, 'Critical'],
    ])
  }

  setTag(val) {
    if (typeof val !== 'string' || val.length < 1 || /[^a-z0-9]/.test(val))
      this.throwHelp(`CAA tag must be a sequence of ASCII letters and numbers in lowercase`)

    if (!this.getTagOptions().has(val)) {
      this.throwHelp(`CAA tag ${val} not recognized`)
    }
    this.set('tag', val)
  }

  getTagOptions() {
    return new Map([['issue'], ['issuewild'], ['iodef']])
  }

  setValue(val) {
    // either (2) a quoted string or
    // (1) a contiguous set of characters without interior spaces
    if (this.isQuoted(val)) {
      val = val.replace(/^["']|["']$/g, '') // strip quotes
    }

    // check if val starts with one of iodefSchemes
    if (this.get('tag') === 'iodef') {
      const iodefSchemes = ['mailto:', 'http:', 'https:']
      if (!iodefSchemes.filter((s) => val.startsWith(s)).length) {
        this.throwHelp(`CAA value must have valid iodefScheme prefix`)
      }
    }

    this.set('value', val)
  }

  getDescription() {
    return 'Certification Authority Authorization'
  }

  getTags() {
    return ['security']
  }

  getQuotedFields() {
    return ['value']
  }

  getRdataFields(arg) {
    return ['flags', 'tag', 'value']
  }

  getRFCs() {
    return [6844, 8659]
  }

  getTypeId() {
    return 257
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'CAA',
      flags: 0,
      tag: 'issue',
      value: 'http://letsencrypt.org',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // CAA via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 257) this.throwHelp('CAA fromTinydns, invalid n')

    const flags = octalToUInt8(rdata.slice(0, 4))
    const taglen = octalToUInt8(rdata.slice(4, 8))

    const unescaped = octalToChar(rdata.slice(8))
    const tag = unescaped.slice(0, taglen)
    const fingerprint = unescaped.slice(taglen)

    return new CAA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'CAA',
      flags,
      tag,
      value: fingerprint,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  CAA flags, tags, value
    const regex =
      /^(?<owner>\S+)\s+(?<ttl>\d{1,10})\s+(?<class>IN)\s+(?<type>CAA)\s+(?<flags>\d+)\s+(?<tag>\w+)\s+(?:"(?<quotedValue>[^"]+)"|(?<unquotedValue>\S+))$/i

    const match = bindline.trim().match(regex)

    if (!match) {
      this.throwHelp(`unable to parse CAA: ${bindline}`)
    }

    const { owner, ttl, class: c, type, flags, tag, quotedValue, unquotedValue } = match.groups

    return new CAA({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      flags: parseInt(flags, 10),
      tag,
      value: quotedValue ?? unquotedValue,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    return this.getTinydnsGeneric(
      UInt8toOctal(this.get('flags')) +
        UInt8toOctal(this.get('tag').length) +
        escapeOctal(/[\r\n\t:\\/]/, this.get('tag')) +
        escapeOctal(/[\r\n\t:\\/]/, this.getQuoted('value')),
    )
  }
}

class CERT extends RR {
  static typeName = 'CERT'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCertType(val) {
    // The type field is the certificate type
    // the type field as an unsigned decimal integer or as a mnemonic symbol
    if (val === undefined || val === null || val === '') {
      this.throwHelp('cert type is required')
    }
    // Accept both mnemonic and numeric, but validate mnemonic
    if (typeof val === 'string') {
      const types = {
        PKIX: 1,
        SPKI: 2,
        PGP: 3,
        IPKIX: 4,
        ISPKI: 5,
        IPGP: 6,
        ACPKIX: 7,
        IACPKIX: 8,
        URI: 253,
        OID: 254,
      }
      if (!Object.hasOwn(types, val)) {
        this.throwHelp(`CERT: unknown cert type mnemonic: ${val}`)
      }
    } else {
      this.is16bitInt('CERT', 'cert type', val)
    }
    this.set('cert type', val)
  }

  getCertTypeValue(val) {
    if (typeof val === 'number') return val
    const types = {
      PKIX: 1,
      SPKI: 2,
      PGP: 3,
      IPKIX: 4,
      ISPKI: 5,
      IPGP: 6,
      ACPKIX: 7,
      IACPKIX: 8,
      URI: 253,
      OID: 254,
    }
    if (Object.hasOwn(types, val)) return types[val]
    this.throwHelp(`CERT: unknown cert type mnemonic: ${val}`)
  }

  setKeyTag(val) {
    // The key tag field is the 16-bit value
    // The key tag field is represented as an unsigned decimal integer.

    this.is16bitInt('CERT', 'key tag', val)

    this.set('key tag', val)
  }

  setAlgorithm(val) {
    // The algorithm field has the same meaning as the algorithm field in DNSKEY
    // The algorithm field is represented as an unsigned decimal integer
    this.is8bitInt('CERT', 'algorithm', val)

    this.set('algorithm', val)
  }

  setCertificate(val) {
    // certificate/CRL portion is represented in base 64 [16] and may be
    // divided into any number of white-space-separated substrings
    if (val === undefined || val === null || val === '') {
      this.throwHelp('certificate is required and cannot be empty')
    }
    this.set('certificate', val)
  }

  getDescription() {
    return 'Certificate'
  }

  getRdataFields() {
    return ['cert type', 'key tag', 'algorithm', 'certificate']
  }

  getRFCs() {
    return [2538, 4398]
  }

  getTypeId() {
    return 37
  }

  getCanonical() {
    return {
      owner: 'mail.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'CERT',
      'cert type': 'PGP',
      'key tag': 0,
      algorithm: 0,
      certificate: 'hexidecimalkeystring1',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const [owner, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 37) this.throwHelp('CERT fromTinydns, invalid n')

    const bytes = Buffer.from(octalToChar(rdata), 'binary')
    const typeNum = bytes.readUInt16BE(0)
    let certType = typeNum

    const types = {
      1: 'PKIX',
      2: 'SPKI',
      3: 'PGP',
      4: 'IPKIX',
      5: 'ISPKI',
      6: 'IPGP',
      7: 'ACPKIX',
      8: 'IACPKIX',
      253: 'URI',
      254: 'OID',
    }
    if (types[typeNum]) certType = types[typeNum]

    return new CERT({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'CERT',
      'cert type': certType,
      'key tag': bytes.readUInt16BE(2),
      algorithm: bytes.readUInt8(4),
      certificate: bytes.slice(5).toString(),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  CERT  certtype, keytag, algo, cert
    const [owner, ttl, c, type, certtype, keytag, algo, certificate] = bindline.split(/\s+/)
    return new CERT({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      'cert type': /^[0-9]+$/.test(certtype) ? parseInt(certtype, 10) : certtype,
      'key tag': parseInt(keytag, 10),
      algorithm: parseInt(algo, 10),
      certificate,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      UInt16toOctal(this.getCertTypeValue(this.get('cert type'))) +
        UInt16toOctal(this.get('key tag')) +
        UInt8toOctal(this.get('algorithm')) +
        escapeOctal(dataRe, this.get('certificate')),
    )
  }
}

class CNAME extends RR {
  static typeName = 'CNAME'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCname(val) {
    // A <domain-name> which specifies the canonical or primary
    // name for the owner.  The owner name is an alias.

    if (!val) this.throwHelp('CNAME: cname is required')

    if (this.isIPv4(val) || this.isIPv6(val)) this.throwHelp(`CNAME: cname must be a FQDN: RFC 2181`)

    if (!this.isFullyQualified('CNAME', 'cname', val)) return
    if (!this.isValidHostname('CNAME', 'cname', val)) return

    // RFC 4034: letters in the DNS names are lower cased
    this.set('cname', val.toLowerCase())
  }

  getDescription() {
    return 'Canonical Name'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['cname']
  }

  getRFCs() {
    return [1035, 2181]
  }

  getTypeId() {
    return 5
  }

  getCanonical() {
    return {
      owner: 'www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'CNAME',
      cname: 'web.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // Cfqdn:p:ttl:timestamp:lo
    const [fqdn, p, ttl, ts, loc] = tinyline.slice(1).split(':')

    return new CNAME({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'CNAME',
      cname: this.fullyQualify(p),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  CNAME  ...
    const [owner, ttl, c, type, cname] = bindline.split(/\s+/)
    return new CNAME({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      cname,
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return this.wirePackDomain(this.get('cname'))
  }

  toTinydns() {
    return `C${this.getTinyFQDN('owner')}:${this.get('cname')}:${this.getTinydnsPostamble()}\n`
  }
}

class DHCID extends RR {
  static typeName = 'DHCID'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setData(val) {
    if (!val) this.throwHelp('DHCID: data is required')
    this.set('data', val)
  }

  getDescription() {
    return 'DHCP Identifier'
  }

  getRdataFields(arg) {
    return ['data']
  }

  getRFCs() {
    return [4701]
  }

  getTypeId() {
    return 49
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DHCID',
      data: 'AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // DHCID via generic, :fqdn:49:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 49) this.throwHelp('DHCID fromTinydns, invalid n')

    return new DHCID({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'DHCID',
      data: octalToBase64(rdata),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // host.example.com  3600  IN  DHCID  <base64data>
    const parts = bindline.split(/\s+/)
    const [owner, ttl, c, type] = parts
    return new DHCID({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      data: parts.slice(4).join(''),
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(base64toOctal(this.get('data')))
  }
}

class DNAME extends RR {
  static typeName = 'DNAME'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTarget(val) {
    if (!val) this.throwHelp('DNAME: target is required')

    if (this.isIPv4(val) || this.isIPv6(val)) this.throwHelp(`DNAME: target must be a domain name`)

    this.isFullyQualified('DNAME', 'target', val)
    this.isValidHostname('DNAME', 'target', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target', val.toLowerCase())
  }

  getDescription() {
    return 'Delegation Name'
  }

  getRdataFields(arg) {
    return ['target']
  }

  getRFCs() {
    return [2672, 6672]
  }

  getTypeId() {
    return 39
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DNAME',
      target: 'example.net.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // DNAME via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 39) this.throwHelp('DNAME fromTinydns, invalid n')

    return new DNAME({
      type: 'DNAME',
      owner: this.fullyQualify(fqdn),
      target: unpackDomainName(rdata)[0],
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  DNAME  ...
    const [owner, ttl, c, type, target] = bindline.split(/\s+/)
    return new DNAME({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      target,
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    const rdata = packDomainName(this.get('target'))
    return this.getTinydnsGeneric(rdata)
  }
}

class DNSKEY extends RR {
  static typeName = 'DNSKEY'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags(val) {
    // a 2 octet Flags Field
    this.is16bitInt('DNSKEY', 'flags', val)

    if (!this.getFlagsOptions().has(val)) {
      this.throwHelp(`DNSKEY: flags must be in the set: ${this.getFlagsOptions()}`)
    }

    this.set('flags', val)
  }

  // possible values are: 0, 256, and 257; RFC 4034
  getFlagsOptions() {
    return new Map([[0], [256], [257]])
  }

  setProtocol(val) {
    // 1 octet
    this.is8bitInt('DNSKEY', 'protocol', val)

    // The Protocol Field MUST be represented as an unsigned decimal integer with a value of 3.
    if (!this.getProtocolOptions().has(val)) this.throwHelp(`DNSKEY: protocol invalid`)

    this.set('protocol', val)
  }

  getProtocolOptions() {
    return new Map([[3]])
  }

  setAlgorithm(val) {
    // 1 octet
    this.is8bitInt('DNSKEY', 'algorithm', val)

    // https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    if (!this.getAlgorithmOptions().has(val)) console.error(`DNSKEY: algorithm (${val}) not recognized`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'RSA/MD5 (DEPRECATED)'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [6, 'DSA-NSEC3-SHA1'],
      [7, 'RSASHA1-NSEC3-SHA1'],
      [8, 'RSA/SHA-256'],
      [9, ''],
      [10, 'RSA/SHA-512'],
      [13, 'ECDSA Curve P-256 with SHA-256'],
      [14, 'ECDSA Curve P-384 with SHA-384'],
      [15, 'Ed25519'],
      [16, 'Ed448'],
      [253],
      [254],
    ])
  }

  setPublickey(val) {
    if (!val) this.throwHelp(`DNSKEY: publickey is required`)

    this.set('publickey', val)
  }

  getDescription() {
    return 'DNS Public Key'
  }

  getTags() {
    return ['dnssec']
  }

  getRdataFields(arg) {
    return ['flags', 'protocol', 'algorithm', 'publickey']
  }

  getRFCs() {
    return [4034, 6014, 8624]
  }

  getTypeId() {
    return 48
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DNSKEY',
      flags: 256,
      protocol: 3,
      algorithm: 5,
      publickey: 'AQPSKAsj8...',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  DNSKEY Flags Protocol Algorithm PublicKey
    const regex =
      /^(?<owner>\S+)\s+(?<ttl>\d+)\s+(?<cls>\w+)\s+(?<type>DNSKEY)\s+(?<flags>\d+)\s+(?<protocol>\d+)\s+(?<algorithm>\d+)\s+(?<publickey>\S.*)$/i

    const match = bindline.trim().match(regex)

    if (!match) {
      this.throwHelp(`unable to parse DNSKEY: ${bindline}`)
    }

    const { owner, ttl, c, type, flags, protocol, algorithm, publickey } = match.groups

    return new DNSKEY({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      flags: parseInt(flags, 10),
      protocol: parseInt(protocol, 10),
      algorithm: parseInt(algorithm, 10),
      publickey: publickey,
    })
  }

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.substring(1).split(':')
    if (n != 48) this.throwHelp('DNSKEY fromTinydns, invalid n')

    const bytes = Buffer.from(octalToChar(rdata), 'binary')

    return new DNSKEY({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'DNSKEY',
      flags: bytes.readUInt16BE(0),
      protocol: bytes.readUInt8(2),
      algorithm: bytes.readUInt8(3),
      publickey: bytes.slice(4).toString(),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('flags')) +
        UInt8toOctal(this.get('protocol')) +
        UInt8toOctal(this.get('algorithm')) +
        escapeOctal(dataRe, this.get('publickey')),
    )
  }
}

class DS extends RR {
  static typeName = 'DS'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setKeyTag(val) {
    // a 2 octet Key Tag field...in network byte order
    if (!val) this.throwHelp(`DS: key tag is required`)
    if (val.length > 2) this.throwHelp(`DS: key tag is too long`)

    this.set('key tag', val)
  }

  setAlgorithm(val) {
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`DS: algorithm invalid`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [253, ''],
      [254, ''],
    ])
  }

  setDigestType(val) {
    if (![1, 2].includes(val)) this.throwHelp(`DS: digest type invalid`)

    this.set('digest type', val)
  }

  setDigest(val) {
    if (!val) this.throwHelp(`DS: digest is required`)

    this.set('digest', val)
  }

  getDescription() {
    return 'Delegation Signer'
  }

  getTags() {
    return ['dnssec']
  }

  getRdataFields(arg) {
    return ['key tag', 'algorithm', 'digest type', 'digest']
  }

  getRFCs() {
    return [4034, 4509]
  }

  getTypeId() {
    return 43
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DS',
      'key tag': 12345,
      algorithm: 5,
      'digest type': 1,
      digest: 'ABCDEF123...',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  DS Key Tag Algorithm, Digest Type, Digest
    const [owner, ttl, c, type, keytag, algorithm, digesttype] = bindline.split(/\s+/)
    return new DS({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      'key tag': parseInt(keytag, 10),
      algorithm: parseInt(algorithm, 10),
      'digest type': parseInt(digesttype, 10),
      digest: bindline.split(/\s+/).slice(7).join(' ').trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 43) this.throwHelp('DS fromTinydns, invalid n')

    const binRdata = Buffer.from(octalToChar(rdata), 'binary')

    return new DS({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'DS',
      'key tag': binRdata.readUInt16BE(0),
      algorithm: binRdata.readUInt8(2),
      'digest type': binRdata.readUInt8(3),
      digest: binRdata.slice(4).toString(),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const rdataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('key tag')) +
        UInt8toOctal(this.get('algorithm')) +
        UInt8toOctal(this.get('digest type')) +
        escapeOctal(rdataRe, this.get('digest')),
    )
  }
}

class HINFO extends RR {
  static typeName = 'HINFO'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCpu(val) {
    if (val.length > 255) this.throwHelp('HINFO cpu cannot exceed 255 chars')
    this.set('cpu', val.replace(/^["']|["']$/g, ''))
  }

  setOs(val) {
    if (val.length > 255) this.throwHelp('HINFO os cannot exceed 255 chars')
    this.set('os', val.replace(/^["']|["']$/g, ''))
  }

  getDescription() {
    return 'Host Info'
  }

  getTags() {
    return ['obsolete']
  }

  getRdataFields(arg) {
    return ['cpu', 'os']
  }

  getRFCs() {
    return [1034, 1035, 8482]
  }

  getTypeId() {
    return 13
  }

  getCanonical() {
    return {
      owner: 'test.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HINFO',
      cpu: 'DEC-2060',
      os: 'TOPS20',
    }
  }

  getQuotedFields() {
    return ['cpu', 'os']
  }

  /******  IMPORTERS   *******/
  fromBind({ bindline }) {
    // test.example.com  3600  IN  HINFO   DEC-2060 TOPS20
    const regex =
      /^(?<owner>\S+)\s+(?<ttl>\d{1,10})\s+(?<class>IN)\s+(?<type>HINFO)\s+(?:"(?<qCPU>[^"]*)"|(?<uCPU>\S+))\s+(?:"(?<qOS>[^"]*)"|(?<uOS>\S+))$/i

    const match = bindline.trim().match(regex)
    if (!match) this.throwHelp(`unable to parse HINFO: ${bindline}`)

    const { owner, ttl, class: c, type, qCPU, uCPU, qOS, uOS } = match.groups

    return new HINFO({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      cpu: qCPU ?? uCPU,
      os: qOS ?? uOS,
    })
  }

  fromTinydns({ tinyline }) {
    // HINFO via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, , rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    const [cpu, os] = [...unpackString(rdata)]

    return new this.constructor({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'HINFO',
      cpu,
      os,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric([packString(this.get('cpu')), packString(this.get('os'))].join(''))
  }
}

class HIP extends RR {
  static typeName = 'HIP'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPkAlgorithm(val) {
    if (val === undefined) this.throwHelp('HIP: pk algorithm is required')
    this.is8bitInt('HIP', 'pk algorithm', val)
    this.set('pk algorithm', val)
  }

  setHit(val) {
    if (!val) this.throwHelp('HIP: hit is required')
    this.set('hit', val)
  }

  setPublicKey(val) {
    if (!val) this.throwHelp('HIP: public key is required')
    this.set('public key', val)
  }

  setRendezvousServers(val) {
    this.set('rendezvous servers', val ?? '')
  }

  getDescription() {
    return 'Host Identity Protocol'
  }

  getRdataFields(arg) {
    return ['pk algorithm', 'hit', 'public key', 'rendezvous servers']
  }

  getRFCs() {
    return [8005]
  }

  getTypeId() {
    return 55
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HIP',
      'pk algorithm': 2,
      hit: '200100107B1A74DF365639CC39F1D578',
      'public key':
        'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA==',
      'rendezvous servers': '',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // HIP via generic, :fqdn:55:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 55) this.throwHelp('HIP fromTinydns, invalid n')

    const bytes = Buffer.from(octalToChar(rdata), 'binary')
    const hitLen = bytes.readUInt8(0)
    const pkAlgorithm = bytes.readUInt8(1)
    const pkLen = bytes.readUInt16BE(2)

    const hit = bytes
      .slice(4, 4 + hitLen)
      .toString('hex')
      .toUpperCase()
    const publicKey = bytes.slice(4 + hitLen, 4 + hitLen + pkLen).toString('base64')

    const rvsNames = []
    let pos = 4 + hitLen + pkLen
    while (pos < bytes.length) {
      const [name, newPos] = unpackDomainName(
        [...bytes.slice(pos)]
          .map((b) => (b < 32 || b > 126 ? UInt8toOctal(b) : String.fromCharCode(b)))
          .join(''),
      )
      pos += newPos
      if (name !== '.') rvsNames.push(name)
    }

    return new HIP({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'HIP',
      'pk algorithm': pkAlgorithm,
      hit,
      'public key': publicKey,
      'rendezvous servers': rvsNames.join(' '),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // owner  ttl  IN  HIP  pk-algorithm HIT public-key [rendezvous-server...]
    const parts = bindline.split(/\s+/)
    const [owner, ttl, c, type, pkAlgorithm, hit, publicKey] = parts
    return new HIP({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      'pk algorithm': parseInt(pkAlgorithm, 10),
      hit,
      'public key': publicKey,
      'rendezvous servers': parts.slice(7).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    const rs = this.get('rendezvous servers')
    const rsPart = rs ? `\t${rs}` : ''
    return `${this.getPrefix(zone_opts)}\t${this.get('pk algorithm')}\t${this.get('hit')}\t${this.get('public key')}${rsPart}\n`
  }

  toTinydns() {
    const hitBytes = Buffer.from(this.get('hit'), 'hex')
    const pkBytes = Buffer.from(this.get('public key'), 'base64')
    const rs = this.get('rendezvous servers')

    let rdata = ''
    rdata += UInt8toOctal(hitBytes.length)
    rdata += UInt8toOctal(this.get('pk algorithm'))
    rdata += UInt16toOctal(pkBytes.length)
    for (const b of hitBytes) rdata += UInt8toOctal(b)
    for (const b of pkBytes) rdata += UInt8toOctal(b)
    if (rs) {
      for (const name of rs.split(/\s+/)) rdata += packDomainName(name)
    }

    return this.getTinydnsGeneric(rdata)
  }
}

class HTTPS extends RR {
  static typeName = 'HTTPS'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('HTTPS', 'priority', val)

    this.set('priority', val)
  }

  setTargetName(val) {
    // this.isFullyQualified('HTTPS', 'target name', val)
    // this.isValidHostname('HTTPS', 'target name', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target name', val.toLowerCase())
  }

  setParams(val) {
    // if (!val) this.throwHelp(`HTTPS: params is required`)

    this.set('params', val)
  }

  getDescription() {
    return 'HTTP Semantics'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['priority', 'target name', 'params']
  }

  getRFCs() {
    return [9460]
  }

  getTypeId() {
    return 65
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HTTPS',
      priority: 1,
      'target name': 'example.com.',
      params: 'alpn="h2,h3"',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  HTTPS Priority TargetName Params
    const [owner, ttl, c, type, pri, fqdn] = bindline.split(/\s+/)
    return new HTTPS({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      priority: parseInt(pri, 10),
      'target name': fqdn,
      params: bindline.split(/\s+/).slice(6).join(' ').trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rd, ttl, ts, loc] = tinyline.slice(1).split(':')

    if (rd.length < 6) {
      this.throwHelp(`HTTPS: RDATA too short: ${rd}`)
    }

    const binary = Buffer.from(octalToChar(rd), 'binary')
    const priority = binary.readUInt16BE(0)

    let pos = 2
    const labels = []
    while (true) {
      const len = binary.readUInt8(pos)
      pos += 1
      if (len === 0) break
      labels.push(binary.slice(pos, pos + len).toString())
      pos += len
    }
    const targetName = `${labels.join('.')}.`
    const params = binary.slice(pos).toString()

    return new HTTPS({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'HTTPS',
      priority,
      'target name': targetName,
      params,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('priority')) +
        packDomainName(this.get('target name')) +
        escapeOctal(dataRe, this.get('params')),
    )
  }
}

class IPSECKEY extends RR {
  static typeName = 'IPSECKEY'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPrecedence(val) {
    // an 8-bit precedence for this record.
    this.is8bitInt('IPSECKEY', 'precedence', val)

    this.set('precedence', val)
  }

  setGatewayType(val) {
    if (!this.getGatewayTypeOptions().has(val)) this.throwHelp(`IPSECKEY: Gateway Type is invalid`)

    this.set('gateway type', val)
  }

  getGatewayTypeOptions() {
    return new Map([
      [0, 'none'],
      [1, '4-byte IPv4'],
      [2, '16-byte IPv6'],
      [3, 'wire encoded domain name'],
    ])
  }

  setAlgorithm(val) {
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`IPSECKEY: Algorithm invalid`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'DSA'],
      [2, 'RSA'],
    ])
  }

  setGateway(val) {
    const type = this.get('gateway type')
    const gwErr = new Error(`IPSECKEY: gateway invalid (${val}) for type ${type}`)
    switch (type) {
      case 0:
        if (val !== '.') throw gwErr
        break
      case 1:
        if (!this.isIPv4(val)) throw gwErr
        break
      case 2:
        if (!this.isIPv6(val)) throw gwErr
        break
    }

    this.set('gateway', val)
  }

  setPublickey(val) {
    // if (val) this.throwHelp(`IPSECKEY: publickey is optional`)

    this.set('publickey', val)
  }

  getDescription() {
    return 'IPsec Keying'
  }

  getTags() {
    return ['security']
  }

  getRdataFields(arg) {
    return ['precedence', 'gateway type', 'algorithm', 'gateway', 'publickey']
  }

  getRFCs() {
    return [4025]
  }

  getTypeId() {
    return 45
  }

  getCanonical() {
    return {
      owner: '38.2.0.192.in-addr.arpa.',
      ttl: 7200,
      class: 'IN',
      type: 'IPSECKEY',
      precedence: 10,
      'gateway type': 1,
      algorithm: 2,
      gateway: '192.0.2.38',
      publickey: 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    }
  }

  /******  IMPORTERS   *******/
  fromBind({ bindline }) {
    // FQDN TTL CLASS IPSECKEY Precedence GatewayType Algorithm Gateway PublicKey
    const [owner, ttl, c, type, prec, gwt, algo, gateway, publickey] = bindline.split(/\s+/)
    return new IPSECKEY({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      precedence: parseInt(prec, 10),
      'gateway type': parseInt(gwt, 10),
      algorithm: parseInt(algo, 10),
      gateway,
      publickey,
    })
  }

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 45) this.throwHelp('IPSECKEY fromTinydns, invalid n')

    const precedence = octalToUInt8(rdata.slice(0, 4))
    const gwType = octalToUInt8(rdata.slice(4, 8))
    const algorithm = octalToUInt8(rdata.slice(8, 12))

    let len, gateway, octalKey

    switch (gwType) {
      case 0: // no gateway
        gateway = rdata.slice(12, 13) // should always be: '.'
        octalKey = rdata.slice(13)
        break
      case 1: // 4-byte IPv4 address
        gateway = octalToIPv4(rdata.slice(12, 28))
        octalKey = rdata.slice(28)
        break
      case 2: // 16-byte IPv6
        gateway = octalToIPv6(rdata.slice(12, 76))
        octalKey = rdata.slice(76)
        break
      case 3: // wire encoded domain name
        ;[gateway, len] = unpackDomainName(rdata.slice(12))
        octalKey = rdata.slice(12 + len)
        break
    }

    return new IPSECKEY({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'IPSECKEY',
      precedence,
      'gateway type': gwType,
      algorithm,
      gateway,
      publickey: octalToBase64(octalKey),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const rdataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    let rdata = ''
    rdata += UInt8toOctal(this.get('precedence'))
    rdata += UInt8toOctal(this.get('gateway type'))
    rdata += UInt8toOctal(this.get('algorithm'))

    switch (this.get('gateway type')) {
      case 0:
        rdata += escapeOctal(rdataRe, '.')
        break
      case 1:
        rdata += ipv4toOctal(this.get('gateway'))
        break
      case 2:
        rdata += ipv6toOctal(this.get('gateway'))
        break
      case 3:
        rdata += packDomainName(this.get('gateway'))
        break
    }

    rdata += base64toOctal(this.get('publickey'))

    return this.getTinydnsGeneric(rdata)
  }
}

class KEY extends RR {
  static typeName = 'KEY'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags(val) {
    // a 2 octet Flags Field
    this.is16bitInt('KEY', 'flags', val)

    this.set('flags', val)
  }

  setProtocol(val) {
    // 1 octet
    this.is8bitInt('KEY', 'protocol', val)

    this.set('protocol', val)
  }

  setAlgorithm(val) {
    // 1 octet

    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`KEY: algorithm invalid`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [253, ''],
      [254, ''],
    ])
  }

  setPublickey(val) {
    if (!val) this.throwHelp(`KEY: publickey is required`)

    this.set('publickey', val)
  }

  getDescription() {
    return 'DNS Public Key'
  }

  getRdataFields(arg) {
    return ['flags', 'protocol', 'algorithm', 'publickey']
  }

  getRFCs() {
    return [2535, 3445]
  }

  getTypeId() {
    return 25
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'KEY',
      flags: 256,
      protocol: 3,
      algorithm: 5,
      publickey: 'AQPSKAsj8...',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  KEY Flags Protocol Algorithm PublicKey
    const [owner, ttl, c, type, flags, protocol, algorithm] = bindline.split(/\s+/)
    return new KEY({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      flags: parseInt(flags, 10),
      protocol: parseInt(protocol, 10),
      algorithm: parseInt(algorithm, 10),
      publickey: bindline.split(/\s+/).slice(7).join(' ').trim(),
    })
  }

  fromTinydns({ tinyline }) {
    // RDATA format: Flags (6 octal chars) + Protocol (3 octal chars) + Algorithm (3 octal chars) + Public Key (escaped data)
    const [owner, _typeId, rd, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (rd.length < 12) {
      this.throwHelp(`KEY: RDATA too short: ${rd}`)
    }

    return new KEY({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'KEY',
      flags: octalToUInt16(rd.slice(0, 6)),
      protocol: octalToUInt8(rd.slice(6, 9)),
      algorithm: octalToUInt8(rd.slice(9, 12)),
      publickey: unescapeOctal(rd.slice(12)),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('flags')) +
        UInt8toOctal(this.get('protocol')) +
        UInt8toOctal(this.get('algorithm')) +
        escapeOctal(dataRe, this.get('publickey')),
    )
  }
}

class KX extends RR {
  static typeName = 'KX'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPreference(val) {
    if (val === undefined) this.throwHelp('KX: preference is required')
    this.is16bitInt('KX', 'preference', val)
    this.set('preference', val)
  }

  setExchanger(val) {
    if (!val) this.throwHelp('KX: exchanger is required')

    this.isFullyQualified('KX', 'exchanger', val)
    this.isValidHostname('KX', 'exchanger', val)

    this.set('exchanger', val.toLowerCase())
  }

  getDescription() {
    return 'Key Exchanger'
  }

  getRdataFields(arg) {
    return ['preference', 'exchanger']
  }

  getRFCs() {
    return [2230]
  }

  getTypeId() {
    return 36
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'KX',
      preference: 10,
      exchanger: 'kx.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // KX via generic, :fqdn:36:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 36) this.throwHelp('KX fromTinydns, invalid n')

    return new KX({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'KX',
      preference: octalToUInt16(rdata.slice(0, 8)),
      exchanger: unpackDomainName(rdata.slice(8))[0],
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  KX  preference exchanger
    const [owner, ttl, c, type, preference, exchanger] = bindline.split(/\s+/)
    return new KX({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      preference: parseInt(preference, 10),
      exchanger,
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.get('preference')}\t${this.getFQDN('exchanger', zone_opts)}\n`
  }

  toTinydns() {
    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('preference')) + packDomainName(this.get('exchanger')),
    )
  }
}

const REF = {
  // RFC 1876
  LATLON: 2 ** 31, // LAT equator, LON prime meridian
  ALTITUDE: 100000 * 100, // reference spheroid used by GPS, in cm
}

const CONV = {
  sec: 1000,
  min: 60 * 1000,
  deg: 60 * 60 * 1000,
}

class LOC extends RR {
  static typeName = 'LOC'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('LOC: address is required')

    /*
    ... LOC ( d1 [m1 [s1]] {"N"|"S"} d2 [m2 [s2]]
             {"E"|"W"} alt["m"] [siz["m"] [hp["m"]
             [vp["m"]]]] )
    */
    this.parseLoc(val)

    this.set('address', val)
  }

  getDescription() {
    return 'Location'
  }

  getRdataFields(arg) {
    return ['address']
  }

  getRFCs() {
    return [1876]
  }

  getTypeId() {
    return 29
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'LOC',
      address: '52 22 23.000 N 4 53 32.000 E 10m 100m 10m 2m',
    }
  }

  parseLoc(string) {
    // d1 [m1 [s1]]
    const dms = '(\\d+)\\s+(?:(\\d+)\\s+)?(?:([\\d.]+)\\s+)?'

    // alt["m"] [siz["m"] [hp["m"] [vp["m"]]]]
    const alt = '(-?[\\d.]+)m?(?:\\s+([\\d.]+)m?)?(?:\\s+([\\d.]+)m?)?(?:\\s+([\\d.]+)m?)?'

    // put them all together
    const locRe = new RegExp(`^${dms}(N|S)\\s+${dms}(E|W)\\s+${alt}`, 'i')
    const r = string.match(locRe)
    if (!r) this.throwHelp('LOC address: invalid format, see RFC 1876')

    const loc = {
      latitude: {
        degrees: r[1],
        minutes: r[2],
        seconds: r[3],
        hemisphere: r[4].toUpperCase(),
      },
      longitude: {
        degrees: r[5],
        minutes: r[6],
        seconds: r[7],
        hemisphere: r[8].toUpperCase(),
      },
      altitude: r[9] * 100, // m -> cm
      size: r[10] * 100,
      precision: {
        horizontal: r[11] * 100,
        vertical: r[12] * 100,
      },
    }

    return loc
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // LOC via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 29) this.throwHelp('LOC fromTinydns, invalid n')

    // divide by 100 is to convert cm to meters
    const l = {
      version: octalToUInt8(rdata.slice(0, 4)),
      size: this.fromExponent(octalToUInt8(rdata.slice(4, 8))),
      precision: {
        horizontal: this.fromExponent(octalToUInt8(rdata.slice(8, 12))),
        vertical: this.fromExponent(octalToUInt8(rdata.slice(12, 16))),
      },
      latitude: this.arcSecToDMS(octalToUInt32(rdata.slice(16, 32)), 'lat'),
      longitude: this.arcSecToDMS(octalToUInt32(rdata.slice(32, 48)), 'lon'),
      altitude: octalToUInt32(rdata.slice(48, 64)) - REF.ALTITUDE,
    }

    return new LOC({
      type: 'LOC',
      owner: this.fullyQualify(fqdn),
      address: this.toHuman(l),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    const [owner, ttl, c, type] = bindline.split(/\s+/)

    return new LOC({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      address: bindline.split(/\s+/).slice(4).join(' ').trim(),
    })
  }

  dmsToArcSec(obj) {
    let retval = obj.degrees * CONV.deg + (obj.minutes ?? 0) * CONV.min + (obj.seconds ?? 0) * CONV.sec
    switch (obj.hemisphere.toUpperCase()) {
      case 'W':
      case 'S':
        retval = -retval
        break
    }
    retval += REF.LATLON
    return retval
  }

  arcSecToDMS(rawmsec, latlon) {
    let msec = Math.abs(rawmsec - REF.LATLON)
    // console.log(`rawmsec: ${rawmsec}, abs msec: ${msec}`)

    const deg = Math.floor(msec / CONV.deg)
    msec -= deg * CONV.deg

    const min = Math.floor(msec / CONV.min)
    msec -= min * CONV.min

    const sec = Math.floor(msec / CONV.sec)
    msec -= sec * CONV.sec

    let hem
    switch (latlon) {
      case 'lat':
        hem = rawmsec >= REF.LATLON ? 'N' : 'S'
        break
      case 'lon':
        hem = rawmsec >= REF.LATLON ? 'E' : 'W'
        break
      default:
        this.throwHelp('unknown or missing hemisphere')
    }

    return `${deg} ${min} ${sec}${msec ? '.' + msec : ''} ${hem}`
  }

  fromExponent(prec) {
    const mantissa = ((prec >> 4) & 0x0f) % 10
    const exponent = ((prec >> 0) & 0x0f) % 10
    return mantissa * Math.pow(10, exponent)
  }

  toExponent(val) {
    /*
     RFC 1876, ... expressed as a pair of four-bit unsigned
     integers, each ranging from zero to nine, with the most
     significant four bits representing the base and the second
     number representing the power of ten by which to multiply
     the base.
    */
    let exponent = 0
    while (val >= 10) {
      val /= 10
      ++exponent
    }
    return (parseInt(val) << 4) | (exponent & 0x0f)
  }

  toHuman(obj) {
    let r = `${obj.latitude} ${obj.longitude} ${obj.altitude / 100}m`
    if (obj.size) r += ` ${obj.size / 100}m`
    if (obj.precision.horizontal) r += ` ${obj.precision.horizontal / 100}m`
    if (obj.precision.vertical) r += ` ${obj.precision.vertical / 100}m`
    return r
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const loc = this.parseLoc(this.get('address'))

    // LOC format declares in meters, tinydns uses cm (hence * 100)
    let rdata = ''
    rdata += UInt8toOctal(0) // version
    rdata += UInt8toOctal(this.toExponent(loc.size))
    rdata += UInt8toOctal(this.toExponent(loc.precision.horizontal))
    rdata += UInt8toOctal(this.toExponent(loc.precision.vertical))
    rdata += UInt32toOctal(this.dmsToArcSec(loc.latitude))
    rdata += UInt32toOctal(this.dmsToArcSec(loc.longitude))
    rdata += UInt32toOctal(loc.altitude + REF.ALTITUDE)

    return this.getTinydnsGeneric(rdata)
  }
}

class MX extends RR {
  static typeName = 'MX'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPreference(val) {
    if (val === undefined) val = this?.default?.preference
    if (val === undefined) this.throwHelp('MX: preference is required')
    this.is16bitInt('MX', 'preference', val)
    this.set('preference', val)
  }

  setExchange(val) {
    if (!val) this.throwHelp('MX: exchange is required')

    if (this.isIPv4(val) || this.isIPv6(val)) this.throwHelp(`MX: exchange must be a FQDN`)

    this.isFullyQualified('MX', 'exchange', val)
    this.isValidHostname('MX', 'exchange', val)

    // RFC 4034: letters in the DNS names ... are lower cased
    this.set('exchange', val.toLowerCase())
  }

  getDescription() {
    return 'Mail Exchanger'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['preference', 'exchange']
  }

  getRFCs() {
    return [1035, 2181, 7505]
  }

  getTypeId() {
    return 15
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 43200,
      class: 'IN',
      type: 'MX',
      preference: 10,
      exchange: 'mail.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // @fqdn:ip:x:dist:ttl:timestamp:lo
    // eslint-disable-next-line no-unused-vars
    const [owner, ip, x, preference, ttl, ts, loc] = tinyline.slice(1).split(':')

    return new MX({
      type: 'MX',
      owner: this.fullyQualify(owner),
      exchange: this.fullyQualify(/\./.test(x) ? x : `${x}.mx.${owner}`),
      preference: parseInt(preference, 10) || 0,
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  MX  preference exchange
    const [owner, ttl, c, type, preference, exchange] = bindline.split(/\s+/)

    return new MX({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      preference: parseInt(preference),
      exchange,
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    const domain = this.wirePackDomain(this.get('exchange'))
    const result = new Uint8Array(2 + domain.length)
    new DataView(result.buffer).setUint16(0, this.get('preference'))
    result.set(domain, 2)
    return result
  }

  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.get('preference')}\t${this.getFQDN('exchange', zone_opts)}\n`
  }

  toTinydns() {
    return `@${this.getTinyFQDN('owner')}::${this.getTinyFQDN('exchange')}:${this.get('preference')}:${this.getTinydnsPostamble()}\n`
  }
}

const rdataRe = /[\r\n\t:\\/]/

class NAPTR extends RR {
  static typeName = 'NAPTR'
  constructor(opts) {
    super(opts)
  }

  getDescription() {
    return 'Naming Authority Pointer'
  }

  getQuotedFields() {
    return ['flags', 'service', 'regexp']
  }

  getRdataFields(arg) {
    return ['order', 'preference', 'flags', 'service', 'regexp', 'replacement']
  }

  getRFCs() {
    return [2915, 3403, 4848]
  }

  getTypeId() {
    return 35
  }

  getCanonical() {
    return {
      owner: 'cid.urn.arpa.',
      ttl: 3600,
      class: 'IN',
      type: 'NAPTR',
      order: 100,
      preference: 10,
      flags: 'S',
      service: 'z3950+N2L+N2R',
      regexp: '',
      replacement: 'gatekeeper.example.com.',
    }
  }

  /****** Resource record specific setters   *******/
  setOrder(val) {
    this.is16bitInt('NAPTR', 'order', val)
    this.set('order', val)
  }

  setPreference(val) {
    this.is16bitInt('NAPTR', 'preference', val)
    this.set('preference', val)
  }

  setFlags(val) {
    if (!this.getFlagsOptions().has(val.toUpperCase())) this.throwHelp(`NAPTR flags are invalid`)

    this.set('flags', val.toUpperCase())
  }

  getFlagsOptions() {
    return new Map([[''], ['S'], ['A'], ['U'], ['P']])
  }

  setService(val) {
    this.set('service', val)
  }

  setRegexp(val) {
    this.set('regexp', val)
  }

  setReplacement(val) {
    this.set('replacement', val)
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // NAPTR via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 35) this.throwHelp('NAPTR fromTinydns, invalid n')

    const binRdata = Buffer.from(octalToChar(rdata), 'binary')

    const rec = {
      type: 'NAPTR',
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
      order: binRdata.readUInt16BE(0, 2),
      preference: binRdata.readUInt16BE(2, 4),
    }

    let idx = 4
    const flagsLength = binRdata.readUInt8(idx)
    idx++
    rec.flags = binRdata.slice(idx, idx + flagsLength).toString()
    idx += flagsLength

    const serviceLen = binRdata.readUInt8(idx)
    idx++
    rec.service = binRdata.slice(idx, idx + serviceLen).toString()
    idx += serviceLen

    const regexpLen = binRdata.readUInt8(idx)
    idx++
    rec.regexp = binRdata.slice(idx, idx + regexpLen).toString()
    idx += regexpLen

    const replaceLen = binRdata.readUInt8(idx)
    idx++
    rec.replacement = binRdata.slice(idx, idx + replaceLen).toString()

    return new NAPTR(rec)
  }

  fromBind({ bindline }) {
    const regex =
      /^(?<owner>\S+)\s+(?<ttl>\d+)\s+(?<class>\S+)\s+(?<type>NAPTR)\s+(?<order>\d+)\s+(?<preference>\d+)\s+["'](?<flags>[^"']*)["']\s+["'](?<service>[^"']*)["']\s+["'](?<regexp>[^"']*)["']\s+(?<replacement>\S+)$/

    const match = bindline.trim().match(regex)

    if (!match) {
      throw new Error(`Invalid NAPTR BIND line: ${bindline}`)
    }

    const { owner, ttl, type, order, preference, flags, service, regexp, replacement } = match.groups

    return new NAPTR({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      class: match.groups.class,
      type,
      order: parseInt(order, 10),
      preference: parseInt(preference, 10),
      flags,
      service,
      regexp,
      replacement,
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    let rdata =
      UInt16toOctal(this.get('order')) +
      UInt16toOctal(this.get('preference')) +
      UInt8toOctal(this.get('flags').length) +
      this.get('flags') +
      UInt8toOctal(this.get('service').length) +
      escapeOctal(rdataRe, this.get('service')) +
      UInt8toOctal(this.get('regexp').length) +
      escapeOctal(rdataRe, this.get('regexp'))

    const replacement = this.get('replacement')
    if (replacement !== '') {
      rdata += UInt8toOctal(replacement.length)
      rdata += escapeOctal(rdataRe, replacement)
    }
    rdata += '\\000'

    return this.getTinydnsGeneric(rdata)
  }
}

class NS extends RR {
  static typeName = 'NS'
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setDname(val) {
    if (!val) this.throwHelp(`NS: dname is required`)

    this.isFullyQualified('NS', 'dname', val)
    this.isValidHostname('NS', 'dname', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('dname', val.toLowerCase())
  }

  getDescription() {
    return 'Name Server'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['dname']
  }

  getRFCs() {
    return [1035]
  }

  getTypeId() {
    return 2
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NS',
      dname: 'ns1.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // &fqdn:ip:x:ttl:timestamp:lo
    // eslint-disable-next-line no-unused-vars
    const [fqdn, ip, dname, ttl, ts, loc] = tinyline.slice(1).split(':')

    return new NS({
      type: 'NS',
      owner: this.fullyQualify(fqdn),
      dname: this.fullyQualify(/\./.test(dname) ? dname : `${dname}.ns.${fqdn}`),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  NS dname
    const [owner, ttl, c, type, dname] = bindline.split(/\s+/)

    return new NS({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      dname: dname,
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return this.wirePackDomain(this.get('dname'))
  }

  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.getFQDN('dname', zone_opts)}\n`
  }

  toTinydns() {
    return `&${this.getTinyFQDN('owner')}::${this.getTinyFQDN('dname')}:${this.getTinydnsPostamble()}\n`
  }
}

class NSEC extends RR {
  static typeName = 'NSEC'
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setNextDomain(val) {
    if (!val) this.throwHelp(`NSEC: 'next domain' is required:`)

    this.isFullyQualified('NSEC', 'next domain', val)
    this.isValidHostname('NSEC', 'next domain', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('next domain', val.toLowerCase())
  }

  setTypeBitMaps(val) {
    if (!val) this.throwHelp(`NSEC: 'type bit maps' is required`)

    this.set('type bit maps', val)
  }

  getDescription() {
    return 'Next Secure'
  }

  getTags() {
    return ['dnssec']
  }

  getRdataFields(arg) {
    return ['next domain', 'type bit maps']
  }

  getRFCs() {
    return [4034]
  }

  getTypeId() {
    return 47
  }

  getCanonical() {
    return {
      owner: 'alfa.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NSEC',
      'next domain': 'host.example.com.',
      'type bit maps': 'A MX RRSIG NSEC TYPE1234',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    const binaryRdata = Buffer.from(octalToChar(rdata), 'binary')
    const [nextDomain, _escapedLen, binaryLen] = unpackDomainName(rdata)

    return new NSEC({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'NSEC',
      'next domain': nextDomain,
      'type bit maps': binaryRdata.slice(binaryLen).toString(),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  NSEC NextDomain TypeBitMaps
    const [owner, ttl, c, type, next] = bindline.split(/\s+/)
    return new NSEC({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'next domain': next,
      'type bit maps': bindline.split(/\s+/).slice(5).filter(removeParens$1).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      packDomainName(this.get('next domain')) + escapeOctal(dataRe, this.get('type bit maps')),
    )
  }
}

const removeParens$1 = (a) => !['(', ')'].includes(a)

class NSEC3 extends RR {
  static typeName = 'NSEC3'
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgorithm(val) {
    // Hash Algorithm is a single octet.
    // The Hash Algorithm field is represented as an unsigned decimal integer.
    if (!val) this.throwHelp(`NSEC3: 'hash algorithm' is required`)

    this.is8bitInt('NSEC3', 'hash algorithm', val)

    this.set('hash algorithm', val)
  }

  setFlags(val) {
    // The Flags field is represented as an unsigned decimal integer.
    if (!val) this.throwHelp(`NSEC3: 'flags' is required`)

    this.is8bitInt('NSEC3', 'flags', val)

    this.set('flags', val)
  }

  setIterations(val) {
    // The Iterations field is represented as an unsigned decimal integer. 0-65535
    if (!val) this.throwHelp(`NSEC3: 'iterations' is required`)

    this.is16bitInt('NSEC3', 'flags', val)

    this.set('iterations', val)
  }

  setSalt(val) {
    // The Salt field is represented as a sequence of case-insensitive
    // hexadecimal digits.  Whitespace is not allowed within the
    // sequence.  The Salt field is represented as "-" (without the
    // quotes) when the Salt Length field has a value of 0
    this.set('salt', val)
  }

  setNextHashedOwnerName(val) {
    // The Next Hashed Owner Name field is represented as an unpadded
    // sequence of case-insensitive base32 digits, without whitespace
    if (!val) this.throwHelp(`NSEC3: 'next hashed owner name' is required`)

    this.set('next hashed owner name', val)
  }

  setTypeBitMaps(val) {
    // The Type Bit Maps field is represented as a sequence of RR type mnemonics.
    if (!val) this.throwHelp(`NSEC3: 'type bit maps' is required`)

    this.set('type bit maps', val)
  }

  getDescription() {
    return 'Next Secure'
  }

  getTags() {
    return ['dnssec']
  }

  getRdataFields(arg) {
    return ['hash algorithm', 'flags', 'iterations', 'salt', 'next hashed owner name', 'type bit maps']
  }

  getRFCs() {
    return [5155, 9077]
  }

  getTypeId() {
    return 50
  }

  getCanonical() {
    return {
      owner: 'test.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NSEC3',
      'hash algorithm': 1,
      flags: 1,
      iterations: 12,
      salt: 'aabbccdd',
      'next hashed owner name': '2vptu5timamqttgl4luu9kg21e0aor3s',
      'type bit maps': 'A RRSIG',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com. 3600 IN NSEC3 1 1 12 aabbccdd (2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG)
    const [owner, ttl, c, type, ha, flags, iterations, salt] = bindline.split(/\s+/)
    const rdata = bindline.split(/\(|\)/)[1]

    return new NSEC3({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'hash algorithm': parseInt(ha, 10),
      flags: parseInt(flags, 10),
      iterations: parseInt(iterations, 10),
      salt,
      'next hashed owner name': rdata.split(/\s+/)[0],
      'type bit maps': rdata.split(/\s+/).slice(1).join('	'),
    })
  }

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 50) this.throwHelp('NSEC3 fromTinydns, invalid n')

    const bytes = Buffer.from(octalToChar(rdata), 'binary')

    const hashAlgorithm = bytes.readUInt8(0)
    const flags = bytes.readUInt8(1)
    const iterations = bytes.readUInt16BE(2)

    // The remaining bytes in the buffer contain:
    // Salt Length (1 octet)
    // Salt (variable length based on Salt Length)
    // Next Hashed Owner Name (variable length)
    // Type Bit Maps (variable length)
    const { salt, nextHashedOwnerName, typeBitMaps } = parseNSEC3Buffer(bytes)

    return new NSEC3({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'NSEC3',
      'hash algorithm': hashAlgorithm,
      flags: flags,
      iterations: iterations,
      salt: salt,
      'next hashed owner name': nextHashedOwnerName,
      'type bit maps': typeBitMaps,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toBind(zone_opts) {
    return `${this.getFQDN('owner', zone_opts)}	${this.get('ttl')}	${this.get('class')}	NSEC3${this.getRdataFields()
      .slice(0, 4)
      .map((f) => '	' + this.get(f))
      .join('')}	(${this.getRdataFields()
      .slice(4)
      .map((f) => this.get(f))
      .join('	')})
`
  }

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      UInt8toOctal(this.get('hash algorithm')) +
        UInt8toOctal(this.get('flags')) +
        UInt16toOctal(this.get('iterations')) +
        escapeOctal(dataRe, this.get('salt')) +
        escapeOctal(dataRe, this.get('next hashed owner name')) +
        escapeOctal(dataRe, this.get('type bit maps')),
    )
  }
}

function parseNSEC3Buffer(bytes) {
  // bytes is a Buffer containing the full RDATA binary (hash alg, flags, iterations, then ASCII salt + next-hashed + type bit maps)
  // Start after the first 4 bytes (hash alg, flags, iterations)
  const rest = bytes.slice(4).toString('utf8')

  // determine expected next hashed owner name length from hash algorithm
  const hashAlgorithm = bytes.readUInt8(0)
  // common mapping: algorithm 1 => SHA-1 => 20 bytes => base32 length 32
  const expectedLen = hashAlgorithm === 1 ? 32 : hashAlgorithm === 2 ? 52 : 32

  // salt length is ambiguous in this representation; try to find a split where
  // the following segment matches expected base32 length
  let salt = ''
  let nextHashedOwnerName = ''
  let typeBitMaps = ''

  const maxSl = Math.min(64, rest.length)
  for (let sl = maxSl; sl >= 1; sl--) {
    const candNext = rest.slice(sl, sl + expectedLen)
    if (candNext.length !== expectedLen) continue
    if (!/^[0-9a-z]+$/.test(candNext)) continue
    // candidate looks like a base32 name; accept and treat remainder as type bit maps
    const saltCandidate = rest.slice(0, sl)
    if (!/^[0-9A-Fa-f]+$/.test(saltCandidate)) continue
    salt = saltCandidate
    nextHashedOwnerName = candNext
    typeBitMaps = rest.slice(sl + expectedLen)
    break
  }

  // fallback: if we couldn't find a split, treat everything up to first non-hex as salt
  if (!nextHashedOwnerName) {
    const saltMatch = rest.match(/^([0-9A-Fa-f]*)/)
    salt = saltMatch ? saltMatch[1] : ''
    nextHashedOwnerName = rest.slice(salt.length)
    typeBitMaps = ''
  }

  return {
    salt,
    nextHashedOwnerName,
    typeBitMaps,
  }
}

class NSEC3PARAM extends RR {
  static typeName = 'NSEC3PARAM'
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgorithm(val) {
    // Hash Algorithm is a single octet.
    // The Hash Algorithm field is represented as an unsigned decimal integer.
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'hash algorithm' is required`)

    this.is8bitInt('NSEC3PARAM', 'hash algorithm', val)

    this.set('hash algorithm', val)
  }

  setFlags(val) {
    // The Flags field is represented as an unsigned decimal integer.
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'flags' is required`)

    this.is8bitInt('NSEC3PARAM', 'flags', val)

    this.set('flags', val)
  }

  setIterations(val) {
    // The Iterations field is represented as an unsigned decimal integer. 0-65535
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'iterations' is required`)

    this.is16bitInt('NSEC3PARAM', 'iterations', val)

    this.set('iterations', val)
  }

  setSalt(val) {
    // The Salt field is represented as a sequence of case-insensitive
    // hexadecimal digits.  Whitespace is not allowed within the
    // sequence.  The Salt field is represented as "-" (without the
    // quotes) when the Salt Length field has a value of 0
    if (val === '-') {
      this.set('salt', val)
      return
    }

    if (val !== undefined && val !== null && !/^[0-9A-Fa-f]*$/.test(val)) {
      this.throwHelp(`NSEC3PARAM: 'salt' must be hex or '-'`)
    }

    this.set('salt', val)
  }

  getDescription() {
    return 'Next Secure Parameters'
  }

  getTags() {
    return ['dnssec']
  }

  getRdataFields(arg) {
    return ['hash algorithm', 'flags', 'iterations', 'salt']
  }

  getRFCs() {
    return [5155]
  }

  getTypeId() {
    return 51
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NSEC3PARAM',
      'hash algorithm': 1,
      flags: 1,
      iterations: 12,
      salt: 'aabbccdd',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  NSEC3PARAM  <hash> <flags> <iterations> <salt>
    // Example: test.example.com. 3600 IN NSEC3PARAM 1 1 12 aabbccdd
    const [owner, ttl, c, type, ha, flags, iterations, salt] = bindline.split(/\s+/)
    return new NSEC3PARAM({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'hash algorithm': parseInt(ha, 10),
      flags: parseInt(flags, 10),
      iterations: parseInt(iterations, 10),
      salt: salt,
    })
  }

  fromTinydns({ tinyline }) {
    // RDATA format: Hash Algorithm (3 octal chars) + Flags (3 octal chars) + Iterations (6 octal chars) + Salt (escaped hex string)
    const [owner, _typeId, rd, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (rd.length < 4) {
      this.throwHelp(`NSEC3PARAM: RDATA too short: ${rd}`)
    }

    // rd may contain actual binary characters (from JS string '\\001' -> char 0x01),
    // so convert via octalToChar and read bytes from a Buffer for robust parsing.
    const bytes = Buffer.from(octalToChar(rd), 'binary')

    return new NSEC3PARAM({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'NSEC3PARAM',
      'hash algorithm': bytes.readUInt8(0),
      flags: bytes.readUInt8(1),
      iterations: bytes.readUInt16BE(2),
      salt: bytes.slice(4).toString('utf8'),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toBind(zone_opts) {
    // Example: test.example.com. 3600 IN NSEC3PARAM 1 1 12 aabbccdd
    return `${this.getFQDN('owner', zone_opts)}	${this.get('ttl')}	${this.get('class')}	NSEC3PARAM	${this.get('hash algorithm')}	${this.get('flags')}	${this.get('iterations')}	${this.get('salt')}
`
  }

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      UInt8toOctal(this.get('hash algorithm')) +
        UInt8toOctal(this.get('flags')) +
        UInt16toOctal(this.get('iterations')) +
        escapeOctal(dataRe, this.get('salt')),
    )
  }
}

class NXT extends RR {
  static typeName = 'NXT'
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setNextDomain(val) {
    if (!val) this.throwHelp(`NXT: 'next domain' is required`)

    this.isFullyQualified('NXT', 'next domain', val)
    this.isValidHostname('NXT', 'next domain', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('next domain', val.toLowerCase())
  }

  setTypeBitMap(val) {
    if (!val) this.throwHelp(`NXT: 'type bit map' is required`)

    this.set('type bit map', val)
  }

  getDescription() {
    return 'Next Secure'
  }

  getTags() {
    return ['deprecated']
  }

  getRdataFields(arg) {
    return ['next domain', 'type bit map']
  }

  getRFCs() {
    return [2065]
  }

  getTypeId() {
    return 30
  }

  getCanonical() {
    return {
      owner: 'big.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NXT',
      'next domain': 'host.example.com.',
      'type bit map': 'A MX NXT',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const [owner, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (parseInt(n, 10) !== this.getTypeId()) this.throwHelp('NXT fromTinydns, invalid n')

    const binaryRdata = Buffer.from(octalToChar(rdata), 'binary')
    const [nextDomain, _escapedLen, binaryLen] = unpackDomainName(rdata)

    return new NXT({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'NXT',
      'next domain': nextDomain,
      'type bit map': binaryRdata.slice(binaryLen).toString(),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  NXT NextDomain TypeBitMap
    const [owner, ttl, c, type, next] = bindline.split(/\s+/)
    return new NXT({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'next domain': next,
      'type bit map': bindline.split(/\s+/).slice(5).filter(removeParens).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      packDomainName(this.get('next domain')) + escapeOctal(dataRe, this.get('type bit map')),
    )
  }
}

const removeParens = (a) => !['(', ')'].includes(a)

class OPENPGPKEY extends RR {
  static typeName = 'OPENPGPKEY'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPublicKey(val) {
    this.set('public key', val)
  }

  getDescription() {
    return 'OpenPGP Public Key'
  }

  getTags() {
    return ['security']
  }

  getRdataFields() {
    return ['public key']
  }

  getRFCs() {
    return [4880, 7929]
  }

  getTypeId() {
    return 61
  }

  getCanonical() {
    return {
      owner: 'matt.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'OPENPGPKEY',
      'public key': 'mQINBFY...',
    }
  }

  /******  IMPORTERS   *******/
  fromBind({ bindline: bindline }) {
    // test.example.com  3600  IN  OPENPGPKEY  <base64 public key>
    const regex =
      /^(?<owner>\S+)\s+(?<ttl>\d{1,10})\s+(?<class>IN)\s+(?<type>OPENPGPKEY)\s+(?<publickey>\S[\s\S]*)$/i
    const match = bindline.trim().match(regex)
    if (!match) this.throwHelp(`unable to parse OPENPGPKEY: ${bindline}`)

    const { owner, ttl, class: c, type, publickey } = match.groups

    return new OPENPGPKEY({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'public key': publickey.trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rd, ttl, ts, loc] = tinyline.slice(1).split(':')
    return new OPENPGPKEY({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'OPENPGPKEY',
      'public key': Buffer.from(unescapeOctal(rd), 'base64').toString('utf-8'),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    const escapedPublicKey = escapeOctal(
      dataRe,
      Buffer.from(this.get('public key'), 'utf-8').toString('base64'),
    )
    return this.getTinydnsGeneric(escapedPublicKey)
  }
}

class PTR extends RR {
  static typeName = 'PTR'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setDname(val) {
    this.isFullyQualified('PTR', 'dname', val)
    this.isValidHostname('PTR', 'dname', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('dname', val.toLowerCase())
  }

  getDescription() {
    return 'Pointer'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['dname']
  }

  getRFCs() {
    return [1035]
  }

  getTypeId() {
    return 12
  }

  getCanonical() {
    return {
      owner: '2.2.0.192.in-addr.arpa.',
      ttl: 3600,
      class: 'IN',
      type: 'PTR',
      dname: 'host.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // ^fqdn:p:ttl:timestamp:lo
    const [fqdn, p, ttl, ts, loc] = tinyline.slice(1).split(':')

    return new PTR({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'PTR',
      dname: this.fullyQualify(p),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  PTR  dname
    const [owner, ttl, c, type, dname] = bindline.split(/\s+/)
    return new PTR({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      dname: dname,
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return this.wirePackDomain(this.get('dname'))
  }

  toTinydns() {
    return `^${this.getTinyFQDN('owner')}:${this.getTinyFQDN('dname')}:${this.getTinydnsPostamble()}\n`
  }
}

class RP extends RR {
  static typeName = 'RP'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setMbox(val) {
    if (!val) this.throwHelp('RP: mbox is required')

    this.isFullyQualified('RP', 'mbox', val)

    this.set('mbox', val.toLowerCase())
  }

  setTxt(val) {
    if (!val) this.throwHelp('RP: txt is required')

    this.isFullyQualified('RP', 'txt', val)

    this.set('txt', val.toLowerCase())
  }

  getDescription() {
    return 'Responsible Person'
  }

  getTags() {
    return ['obsolete']
  }

  getRdataFields(arg) {
    return ['mbox', 'txt']
  }

  getRFCs() {
    return [1183]
  }

  getTypeId() {
    return 17
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'RP',
      mbox: 'admin.example.com.',
      txt: 'info.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromBind({ bindline }) {
    // test.example.com  3600  IN  RP  mbox txt
    const [owner, ttl, c, type, mbox, txt] = bindline.split(/\s+/)
    return new RP({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      mbox,
      txt,
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')

    const [mbox, consumed] = unpackDomainName(rdata)
    const txt = unpackDomainName(rdata.slice(consumed))[0]

    return new RP({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'RP',
      mbox,
      txt,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.getFQDN('mbox', zone_opts)}\t${this.getFQDN('txt', zone_opts)}\n`
  }

  toTinydns() {
    return this.getTinydnsGeneric(packDomainName(this.get('mbox')) + packDomainName(this.get('txt')))
  }
}

class RRSIG extends RR {
  static typeName = 'RRSIG'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTypeCovered(val) {
    // a 2 octet Type Covered field
    if (!val) this.throwHelp(`RRSIG: 'type covered' is required`)
    if (val.length > 2) this.throwHelp(`RRSIG: 'type covered' is too long`)

    this.set('type covered', val)
  }

  setAlgorithm(val) {
    // a 1 octet Algorithm field
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`RRSIG: algorithm invalid`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'RRSIGA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [253],
      [254],
    ])
  }

  setLabels(val) {
    // a 1 octet Labels field
    this.is8bitInt('RRSIG', 'labels', val)

    this.set('labels', val)
  }

  setOriginalTtl(val) {
    // a 4 octet Original TTL field
    this.is32bitInt('RRSIG', 'original ttl', val)

    this.set('original ttl', val)
  }

  setSignatureExpiration(val) {
    // a 4 octet Signature Expiration field
    this.set('signature expiration', val)
  }

  setSignatureInception(val) {
    // a 4 octet Signature Inception field
    this.set('signature inception', val)
  }

  setKeyTag(val) {
    // a 2 octet Key tag
    this.set('key tag', val)
  }

  setSignersName(val) {
    // the Signer's Name field
    this.set('signers name', val)
  }

  setSignature(val) {
    // the Signature field.

    this.set('signature', val)
  }

  getDescription() {
    return 'Resource Record Signature'
  }

  getTags() {
    return ['dnssec']
  }

  getRdataFields(arg) {
    return [
      'type covered',
      'algorithm',
      'labels',
      'original ttl',
      'signature expiration',
      'signature inception',
      'key tag',
      'signers name',
      'signature',
    ]
  }

  getRFCs() {
    return [4034]
  }

  getTypeId() {
    return 46
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'RRSIG',
      'type covered': 1,
      algorithm: 5,
      labels: 3,
      'original ttl': 3600,
      'signature expiration': 1045053120,
      'signature inception': 1042461120,
      'key tag': 12345,
      'signers name': 'example.com.',
      signature: 'ABCDEF...',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // example.com. 3600 IN RRSIG typecovered algorithm labels origttl sigexp siginc keytag signersname ( signature )
    const parts = bindline.trim().split(/\s+/)
    return new RRSIG({
      owner: parts[0],
      ttl: parseInt(parts[1], 10),
      class: parts[2],
      type: 'RRSIG',
      'type covered': parseInt(parts[4], 10),
      algorithm: parseInt(parts[5], 10),
      labels: parseInt(parts[6], 10),
      'original ttl': parseInt(parts[7], 10),
      'signature expiration': parseInt(parts[8], 10),
      'signature inception': parseInt(parts[9], 10),
      'key tag': parseInt(parts[10], 10),
      'signers name': parts[11],
      signature: parts
        .slice(12)
        .filter((a) => a !== '(' && a !== ')')
        .join(' ')
        .trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (parseInt(n, 10) !== this.getTypeId()) this.throwHelp('RRSIG fromTinydns, invalid n')

    const bytes = Buffer.from(octalToChar(rdata), 'binary')
    const typeCovered = bytes.readUInt16BE(0)
    const algorithm = bytes.readUInt8(2)
    const labels = bytes.readUInt8(3)
    const originalTtl = bytes.readUInt32BE(4)
    const signatureExpiration = bytes.readUInt32BE(8)
    const signatureInception = bytes.readUInt32BE(12)
    const keyTag = bytes.readUInt16BE(16)

    let pos = 18
    const labelArr = []
    while (pos < bytes.length) {
      const len = bytes.readUInt8(pos++)
      if (len === 0) break
      labelArr.push(bytes.slice(pos, pos + len).toString())
      pos += len
    }
    const signersName = `${labelArr.join('.')}.`
    const signature = bytes.slice(pos).toString()

    return new RRSIG({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'RRSIG',
      'type covered': typeCovered,
      algorithm,
      labels,
      'original ttl': originalTtl,
      'signature expiration': signatureExpiration,
      'signature inception': signatureInception,
      'key tag': keyTag,
      'signers name': signersName,
      signature,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.get('type covered')}\t${this.get('algorithm')}\t${this.get('labels')}\t${this.get('original ttl')}\t${this.get('signature expiration')}\t${this.get('signature inception')}\t${this.get('key tag')}\t${this.getFQDN('signers name', zone_opts)}\t${this.get('signature')}\n`
  }

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:]/, 'g')
    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('type covered')) +
        UInt8toOctal(this.get('algorithm')) +
        UInt8toOctal(this.get('labels')) +
        UInt32toOctal(this.get('original ttl')) +
        UInt32toOctal(this.get('signature expiration')) +
        UInt32toOctal(this.get('signature inception')) +
        UInt16toOctal(this.get('key tag')) +
        packDomainName(this.get('signers name')) +
        escapeOctal(dataRe, this.get('signature')),
    )
  }
}

class SIG extends RR {
  static typeName = 'SIG'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTypeCovered(val) {
    // a 2 octet Type Covered field
    if (!val) this.throwHelp(`SIG: 'type covered' is required`)

    this.set('type covered', val)
  }

  setAlgorithm(val) {
    // a 1 octet Algorithm field
    this.is8bitInt('SIG', 'algorithm', val)

    this.set('algorithm', val)
  }

  setLabels(val) {
    // a 1 octet Labels field
    this.is8bitInt('SIG', 'labels', val)

    this.set('labels', val)
  }

  setOriginalTtl(val) {
    // a 4 octet Original TTL field
    this.is32bitInt('SIG', 'original ttl', val)

    this.set('original ttl', val)
  }

  setSignatureExpiration(val) {
    // a 4 octet Signature Expiration field
    this.set('signature expiration', val)
  }

  setSignatureInception(val) {
    // a 4 octet Signature Inception field
    this.set('signature inception', val)
  }

  setKeyTag(val) {
    // a 2 octet Key tag
    this.set('key tag', val)
  }

  setSignersName(val) {
    // the domain name of the signer generating the SIG RR

    // RFC 4034: letters in the DNS names are lower cased
    this.set('signers name', val.toLowerCase())
  }

  setSignature(val) {
    // the Signature field.

    this.set('signature', val)
  }

  getDescription() {
    return 'Signature'
  }

  getTags() {
    return ['obsolete']
  }

  getRdataFields(arg) {
    return [
      'type covered',
      'algorithm',
      'labels',
      'original ttl',
      'signature expiration',
      'signature inception',
      'key tag',
      'signers name',
      'signature',
    ]
  }

  getRFCs() {
    return [2535, 3755]
  }

  getTypeId() {
    return 24
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SIG',
      'type covered': 1,
      algorithm: 5,
      labels: 3,
      'original ttl': 3600,
      'signature expiration': 1045053120,
      'signature inception': 1042461120,
      'key tag': 12345,
      'signers name': 'example.com.',
      signature: 'ABCDEF...',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // example.com. 3600 IN SIG TypeCovered Algorithm Labels OrigTTL SigExpiration SigInception KeyTag SignersName ( Signature )
    const parts = bindline.trim().split(/\s+/)

    return new SIG({
      owner: parts[0],
      ttl: parseInt(parts[1], 10),
      class: parts[2],
      type: 'SIG',
      'type covered': parseInt(parts[4], 10),
      algorithm: parseInt(parts[5], 10),
      labels: parseInt(parts[6], 10),
      'original ttl': parseInt(parts[7], 10),
      'signature expiration': parseInt(parts[8], 10),
      'signature inception': parseInt(parts[9], 10),
      'key tag': parseInt(parts[10], 10),
      'signers name': parts[11],
      signature: parts
        .slice(12)
        .filter((a) => a !== '(' && a !== ')')
        .join(' ')
        .trim(),
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:]/, 'g')

    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('type covered')) +
        UInt8toOctal(this.get('algorithm')) +
        UInt8toOctal(this.get('labels')) +
        UInt32toOctal(this.get('original ttl')) +
        UInt32toOctal(this.get('signature expiration')) +
        UInt32toOctal(this.get('signature inception')) +
        UInt16toOctal(this.get('key tag')) +
        packDomainName(this.get('signers name')) +
        escapeOctal(dataRe, this.get('signature')),
    )
  }

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.substring(1).split(':')
    if (parseInt(n, 10) !== this.getTypeId()) this.throwHelp('SIG fromTinydns, invalid n')

    const bytes = Buffer.from(octalToChar(rdata), 'binary')

    const typeCovered = bytes.readUInt16BE(0)
    const algorithm = bytes.readUInt8(2)
    const labels = bytes.readUInt8(3)
    const originalTtl = bytes.readUInt32BE(4)
    const signatureExpiration = bytes.readUInt32BE(8)
    const signatureInception = bytes.readUInt32BE(12)
    const keyTag = bytes.readUInt16BE(16)

    // parse signers name from binary buffer starting at offset 18
    let pos = 18
    const labelsArr = []
    while (pos < bytes.length) {
      const len = bytes.readUInt8(pos++)
      if (len === 0) break
      labelsArr.push(bytes.slice(pos, pos + len).toString())
      pos += len
    }
    const signersName = `${labelsArr.join('.')}.`

    const signature = bytes.slice(pos).toString()

    return new SIG({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SIG',
      'type covered': typeCovered,
      algorithm,
      labels,
      'original ttl': originalTtl,
      'signature expiration': signatureExpiration,
      'signature inception': signatureInception,
      'key tag': keyTag,
      'signers name': signersName,
      signature,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  toBind(zone_opts) {
    return `${this.getFQDN('owner', zone_opts)}	${this.get('ttl')}	${this.get('class')}	SIG${this.getRdataFields()
      .slice(0, 4)
      .map((f) => '	' + this.get(f))
      .join('')}	${this.getRdataFields()
      .slice(4, 8)
      .map((f) => this.get(f))
      .join('	')}	( ${this.get('signature')} )`
  }
}

class SMIMEA extends RR {
  static typeName = 'SMIMEA'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCertificateUsage(val) {
    if (!this.getCertificateUsageOptions().has(val)) this.throwHelp(`SMIMEA: certificate usage invalid`)

    this.set('certificate usage', val)
  }

  getCertificateUsageOptions() {
    return new Map([
      [0, 'CA certificate'],
      [1, 'an end entity certificate'],
      [2, 'the trust anchor'],
      [3, 'domain-issued certificate'],
    ])
  }

  setSelector(val) {
    if (!this.getSelectorOptions().has(val)) this.throwHelp(`SMIMEA: selector invalid`)

    this.set('selector', val)
  }

  getSelectorOptions() {
    return new Map([
      [0, 'Full certificate'],
      [1, 'SubjectPublicKeyInfo'],
    ])
  }

  setMatchingType(val) {
    if (!this.getMatchingTypeOptions().has(val)) this.throwHelp(`SMIMEA: matching type`)

    this.set('matching type', val)
  }

  getMatchingTypeOptions() {
    return new Map([
      [0, 'Exact match'],
      [1, 'SHA-256 hash'],
      [2, 'SHA-512 hash'],
    ])
  }

  setCertificateAssociationData(val) {
    this.set('certificate association data', val)
  }

  getDescription() {
    return 'S/MIME cert association'
  }

  getTags() {
    return ['security']
  }

  getRdataFields(arg) {
    return ['certificate usage', 'selector', 'matching type', 'certificate association data']
  }

  getRFCs() {
    return [8162]
  }

  getTypeId() {
    return 53
  }

  getCanonical() {
    return {
      owner: '_443._tcp.www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SMIMEA',
      'certificate usage': 0,
      selector: 0,
      'matching type': 1,
      'certificate association data': 'ABCDEF...',
    }
  }

  getQuotedFields() {
    return []
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  SMIMEA, usage, selector, match, data
    const [owner, ttl, c, type, usage, selector, match] = bindline.split(/\s+/)
    return new SMIMEA({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'certificate usage': parseInt(usage, 10),
      selector: parseInt(selector, 10),
      'matching type': parseInt(match, 10),
      'certificate association data': bindline.split(/\s+/).slice(7).join(' ').trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    const binaryRdata = Buffer.from(octalToChar(rdata), 'binary')

    return new SMIMEA({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'SMIMEA',
      'certificate usage': binaryRdata.readUInt8(0),
      selector: binaryRdata.readUInt8(1),
      'matching type': binaryRdata.readUInt8(2),
      'certificate association data': binaryRdata.slice(3).toString(),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      UInt8toOctal(this.get('certificate usage')) +
        UInt8toOctal(this.get('selector')) +
        UInt8toOctal(this.get('matching type')) +
        escapeOctal(dataRe, this.get('certificate association data')),
    )
  }
}

class SOA extends RR {
  static typeName = 'SOA'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setMinimum(val) {
    // minimum (used for negative caching, since RFC 2308)
    // RFC 1912 sugggests 1-5 days
    // RIPE recommends 3600 (1 hour)
    this.is32bitInt('SOA', 'minimum', val)

    this.set('minimum', val)
  }

  setMname(val) {
    // MNAME (primary NS)
    this.isValidHostname('SOA', 'MNAME', val)
    this.isFullyQualified('SOA', 'MNAME', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('mname', val.toLowerCase())
  }

  setRname(val) {
    // RNAME (email of admin)  (escape . with \)
    this.isValidHostname('SOA', 'RNAME', val)
    this.isFullyQualified('SOA', 'RNAME', val)
    if (/@/.test(val)) this.throwHelp(`SOA rname replaces @ with a . (dot)`)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('rname', val.toLowerCase())
  }

  setSerial(val) {
    this.is32bitInt('SOA', 'serial', val)

    this.set('serial', val)
  }

  setRefresh(val) {
    // refresh (seconds after which to check with master for update)
    // RFC 1912 suggests 20 min to 12 hours
    // RIPE recommends 86400 (24 hours)
    this.is32bitInt('SOA', 'refresh', val)

    this.set('refresh', val)
  }

  setRetry(val) {
    // seconds after which to retry serial # update
    // RIPE recommends 7200 seconds (2 hours)

    this.is32bitInt('SOA', 'retry', val)

    this.set('retry', val)
  }

  setExpire(val) {
    // seconds after which secondary should drop zone if no master response
    // RFC 1912 suggests 2-4 weeks
    // RIPE suggests 3600000 (1,000 hours, 6 weeks)
    this.is32bitInt('SOA', 'expire', val)

    this.set('expire', val)
  }

  getDescription() {
    return 'Start Of Authority'
  }

  getRdataFields(arg) {
    return ['mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum']
  }

  getRFCs() {
    return [1035, 2308]
  }

  getTypeId() {
    return 6
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SOA',
      mname: 'ns1.example.com.',
      rname: 'admin.example.com.',
      serial: 2023051001,
      refresh: 7200,
      retry: 3600,
      expire: 1209600,
      minimum: 3600,
    }
  }

  /******  IMPORTERS   *******/
  fromBind({ bindline }) {
    // example.com TTL IN  SOA mname rname serial refresh retry expire minimum
    const [owner, ttl, c, type, mname, rname, serial, refresh, retry, expire, minimum] =
      bindline.split(/[\s+]/)

    return new SOA({
      owner,
      ttl: parseInt(ttl) || parseInt(minimum),
      class: c,
      type,
      mname,
      rname,
      serial: parseInt(serial, 10),
      refresh: parseInt(refresh, 10),
      retry: parseInt(retry, 10),
      expire: parseInt(expire, 10),
      minimum: parseInt(minimum, 10),
    })
  }

  fromTinydns({ tinyline }) {
    // Zfqdn:mname:rname:ser:ref:ret:exp:min:ttl:time:lo
    const [fqdn, mname, rname, ser, ref, ret, exp, min, ttl, ts, loc] = tinyline.slice(1).split(':')

    return new SOA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SOA',
      mname: this.fullyQualify(mname),
      rname: this.fullyQualify(rname),
      serial: parseInt(ser ?? this.default?.serial, 10),
      refresh: parseInt(ref, 10) || 16384,
      retry: parseInt(ret, 10) || 2048,
      expire: parseInt(exp, 10) || 1048576,
      minimum: parseInt(min, 10) || 2560,
      timestamp: parseInt(ts) || '',
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    const numFields = ['serial', 'refresh', 'retry', 'expire', 'minimum']
    return `${this.getFQDN('owner', zone_opts)}\t${this.get('ttl')}\t${this.get('class')}\tSOA\t${this.getFQDN('mname', zone_opts)}\t${this.getFQDN('rname', zone_opts)}${numFields.map((f) => '\t' + this.get(f)).join('')}\n`
  }

  toMaraDNS() {
    return `${this.get('owner')}\t SOA\t${this.getRdataFields()
      .map((f) => this.getQuoted(f))
      .join('\t')} ~\n`
  }

  getWireRdata() {
    const mname = this.wirePackDomain(this.get('mname'))
    const rname = this.wirePackDomain(this.get('rname'))
    const result = new Uint8Array(mname.length + rname.length + 20)
    let offset = 0
    result.set(mname, offset)
    offset += mname.length
    result.set(rname, offset)
    offset += rname.length
    const view = new DataView(result.buffer, offset)
    view.setUint32(0, this.get('serial'))
    view.setUint32(4, this.get('refresh'))
    view.setUint32(8, this.get('retry'))
    view.setUint32(12, this.get('expire'))
    view.setUint32(16, this.get('minimum'))
    return result
  }

  toTinydns() {
    return `Z${this.getTinyFQDN('owner')}:${this.getTinyFQDN('mname')}:${this.getTinyFQDN('rname')}:${this.getEmpty('serial')}:${this.getEmpty('refresh')}:${this.getEmpty('retry')}:${this.getEmpty('expire')}:${this.getEmpty('minimum')}:${this.getTinydnsPostamble()}\n`
  }
}

class TXT extends RR {
  static typeName = 'TXT'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setData(val) {
    this.set('data', val)
  }

  getDescription() {
    return 'Text'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['data']
  }

  getRFCs() {
    return [1035, 4408, 7208, 6376]
  }

  getTypeId() {
    return 16
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'TXT',
      data: 'v=spf1 mx -all',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    const str = tinyline
    let fqdn, rdata, s, ttl, ts, loc
    // 'fqdn:s:ttl:timestamp:lo
    if (str[0] === "'") {
      ;[fqdn, s, ttl, ts, loc] = str.slice(1).split(':')
      rdata = octalToChar(s)
    } else {
      ;[fqdn, rdata, ttl, ts, loc] = this.fromTinydnsGeneric(str)
    }

    return new this.constructor({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'TXT',
      data: rdata,
      timestamp: ts,
      location: loc?.trim() || '',
    })
  }

  fromTinydnsGeneric(str) {
    // generic: :fqdn:n:rdata:ttl:timestamp:location
    // eslint-disable-next-line prefer-const
    let [fqdn, n, rdata, ttl, ts, loc] = str.slice(1).split(':')
    if (n != 16) this.throwHelp('TXT fromTinydns, invalid n')

    rdata = octalToChar(rdata)
    let s = ''
    let len = rdata[0].charCodeAt(0)
    let pos = 1
    while (pos < rdata.length) {
      s += rdata.slice(pos, +(len + pos))
      pos = len + pos
      len = rdata.charCodeAt(pos + 1)
    }
    return [fqdn, s, ttl, ts, loc]
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  TXT  "..."
    const regex = /^(?<owner>\S{1,255})\s+(?<ttl>\d{1,10})\s+(?<cls>IN)\s+(?<type>\w{3})\s+(?<rdata>\S.*)$/i
    const match = bindline.trim().match(regex)
    if (!match) this.throwHelp(`unable to parse TXT: ${bindline}`)

    const { owner, ttl, cls, type, rdata } = match.groups

    return new this.constructor({
      owner,
      ttl: parseInt(ttl, 10),
      class: cls,
      type: type.toUpperCase(),
      data: rdata
        .match(/"([^"]+?)"/g)
        .map((s) => s.replace(/^"|"$/g, ''))
        .join(''),
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t"${asQuotedStrings(this.get('data'))}"\n`
  }

  toMaraDNS() {
    const data = asQuotedStrings(this.get('data')).replace(/"/g, "'")
    return `${this.get('owner')}\t+${this.get('ttl')}\t${this.get('type')}\t'${data}' ~\n`
  }

  getWireRdata() {
    let data = this.get('data')
    if (Array.isArray(data)) data = data.join('')
    return packStringWire(data)
  }

  toTinydns() {
    let data = this.get('data')
    if (Array.isArray(data)) data = data.join('')
    const rdata = escapeOctal(new RegExp(/[\r\n\t:\\/]/, 'g'), data)
    return `'${this.getTinyFQDN('owner')}:${rdata}:${this.getTinydnsPostamble()}\n`
  }
}

function asQuotedStrings(data) {
  // BIND croaks when any string in the TXT RR data is longer than 255
  if (Array.isArray(data)) {
    let hasTooLong = false
    for (const str of data) {
      if (str.length > 255) hasTooLong = true
    }
    return hasTooLong
      ? data
          .join('')
          .match(/(.{1,255})/g)
          .join('" "')
      : data.join('" "')
  }

  if (data.length > 255) {
    return data.match(/(.{1,255})/g).join('" "')
  }

  return data
}

function packStringWire(str) {
  const enc = new TextEncoder()
  const parts = str.match(/(.{1,255})/g)
  let len = 0
  for (const part of parts) len += part.length + 1

  const buf = new Uint8Array(len)
  let offset = 0
  for (const part of parts) {
    buf[offset++] = part.length
    buf.set(enc.encode(part), offset)
    offset += part.length
  }
  return buf
}

// obsoleted by RFC 7208

class SPF extends TXT {
  static typeName = 'SPF'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setData(val) {
    this.set('data', val)
  }

  getDescription() {
    return 'Sender Policy Framework'
  }

  getTags() {
    return ['deprecated']
  }

  getRdataFields(arg) {
    return ['data']
  }

  getRFCs() {
    return [4408, 7208]
  }

  getTypeId() {
    return 99
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SPF',
      data: 'v=spf1 mx -all',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // SPF via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 99) this.throwHelp('SPF fromTinydns, invalid n')

    return new SPF({
      type: 'SPF',
      owner: this.fullyQualify(fqdn),
      data: octalToChar(rdata),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    const rdata = escapeOctal(new RegExp(/[\r\n\t:\\/]/, 'g'), this.get('data'))
    return this.getTinydnsGeneric(rdata)
  }
}

class SRV extends RR {
  static typeName = 'SRV'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('SRV', 'priority', val)

    this.set('priority', val)
  }

  setPort(val) {
    this.is16bitInt('SRV', 'port', val)

    this.set('port', val)
  }

  setWeight(val) {
    this.is16bitInt('SRV', 'weight', val)

    this.set('weight', val)
  }

  setTarget(val) {
    if (!val) this.throwHelp(`SRV: target is required`)

    if (this.isIPv4(val) || this.isIPv6(val)) this.throwHelp(`SRV: target must be a FQDN`)

    this.isFullyQualified('SRV', 'target', val)
    this.isValidHostname('SRV', 'target', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target', val.toLowerCase())
  }

  getDescription() {
    return 'Service'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['priority', 'weight', 'port', 'target']
  }

  getRFCs() {
    return [2782]
  }

  getTypeId() {
    return 33
  }

  getCanonical() {
    return {
      owner: '_imaps._tcp.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SRV',
      priority: 10,
      weight: 10,
      port: 993,
      target: 'mail.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    const str = tinyline
    let fqdn, addr, port, pri, weight, ttl, ts, loc, n, rdata

    if (str[0] === 'S') {
      ;[fqdn, addr, port, pri, weight, ttl, ts, loc] = str.slice(1).split(':')
    } else {
      ;[fqdn, n, rdata, ttl, ts, loc] = str.slice(1).split(':')
      if (n != 33) this.throwHelp('SRV fromTinydns: invalid n')

      pri = octalToUInt16(rdata.slice(0, 8))
      weight = octalToUInt16(rdata.slice(8, 16))
      port = octalToUInt16(rdata.slice(16, 24))
      addr = unpackDomainName(rdata.slice(24))[0]
    }

    return new SRV({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SRV',
      priority: parseInt(pri, 10),
      weight: parseInt(weight, 10),
      port: parseInt(port, 10),
      target: this.fullyQualify(addr),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  SRV Priority Weight Port Target
    const [owner, ttl, c, type, pri, weight, port, target] = bindline.split(/\s+/)
    return new SRV({
      owner: owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      priority: parseInt(pri, 10),
      weight: parseInt(weight, 10),
      port: parseInt(port, 10),
      target: target,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    let rdata = ''

    for (const e of ['priority', 'weight', 'port']) {
      rdata += UInt16toOctal(this.get(e))
    }

    rdata += packDomainName(this.get('target'))

    return this.getTinydnsGeneric(rdata)
  }
}

class SSHFP extends RR {
  static typeName = 'SSHFP'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAlgorithm(val) {
    this.is8bitInt('SSHFP', 'algorithm', val)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    return new Map([
      [0, 'reserved'],
      [1, 'RSA'],
      [2, 'DSA'],
      [3, 'ECDSA'],
      [4, 'Ed25519'],
      [6, 'Ed448'],
    ])
  }

  setFptype(val) {
    this.is8bitInt('SSHFP', 'fptype', val)

    this.set('fptype', val)
  }

  getFptypeOptions() {
    return new Map([
      [0, 'reserved'],
      [1, 'SHA-1'],
      [2, 'SHA-256'],
    ])
  }

  setFingerprint(val) {
    this.set('fingerprint', val)
  }

  getDescription() {
    return 'Secure Shell Key Fingerprints'
  }

  getTags() {
    return ['security']
  }

  getRdataFields() {
    return ['algorithm', 'fptype', 'fingerprint']
  }

  getRFCs() {
    return [4255, 7479, 8709]
  }

  getTypeId() {
    return 44
  }

  getCanonical() {
    return {
      owner: 'mail.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SSHFP',
      algorithm: 2,
      fptype: 1,
      fingerprint: '123456789abcdef6789abcdf6789abdf6789abcd',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // SSHFP via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 44) this.throwHelp('SSHFP fromTinydns, invalid n')

    return new SSHFP({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SSHFP',
      algorithm: octalToUInt8(rdata.slice(0, 4)),
      fptype: octalToUInt8(rdata.slice(4, 8)),
      fingerprint: octalToHex(rdata.slice(8)),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  SSHFP  algo fptype fp
    const [owner, ttl, c, type, algo, fptype, fp] = bindline.split(/\s+/)
    return new SSHFP({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      algorithm: parseInt(algo, 10),
      fptype: parseInt(fptype, 10),
      fingerprint: fp,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    return this.getTinydnsGeneric(
      UInt8toOctal(this.get('algorithm')) +
        UInt8toOctal(this.get('fptype')) +
        packHex(this.get('fingerprint')),
    )
  }
}

class SVCB extends RR {
  static typeName = 'SVCB'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('SVCB', 'priority', val)

    this.set('priority', val)
  }

  setTargetName(val) {
    // this.isFullyQualified('SVCB', 'target name', val)
    // this.isValidHostname('SVCB', 'target name', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target name', val.toLowerCase())
  }

  setParams(val) {
    // if (!val) throw new Error(`SVCB: params is required`)

    this.set('params', val)
  }

  getDescription() {
    return 'Service Binding'
  }

  getRdataFields(arg) {
    return ['priority', 'target name', 'params']
  }

  getRFCs() {
    return [9460]
  }

  getTypeId() {
    return 64
  }

  getCanonical() {
    return {
      owner: '_8443._foo.api.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SVCB',
      priority: 1,
      'target name': 'svc4.example.net.',
      params: 'alpn="h2,h3"',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  SVCB Priority TargetName Params
    // _8443._foo.api.example.com. 7200 IN SVCB 0 svc4.example.net.
    // svc4.example.net.  7200  IN SVCB 3 svc4.example.net. ( alpn="bar" port="8004" )
    const [owner, ttl, c, type, pri, fqdn] = bindline.split(/\s+/)
    return new SVCB({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      priority: parseInt(pri, 10),
      'target name': fqdn,
      params: bindline.split(/\s+/).slice(6).join(' ').trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rd, ttl, ts, loc] = tinyline.slice(1).split(':')

    if (rd.length < 6) {
      this.throwHelp(`SVCB: RDATA too short: ${rd}`)
    }

    // Convert escaped octal RDATA into a binary buffer for reliable parsing
    const binary = Buffer.from(octalToChar(rd), 'binary')

    const priority = binary.readUInt16BE(0)

    // parse domain name from binary starting at offset 2
    let pos = 2
    const labels = []
    while (true) {
      const len = binary.readUInt8(pos)
      pos += 1
      if (len === 0) break
      labels.push(binary.slice(pos, pos + len).toString())
      pos += len
    }
    const targetName = `${labels.join('.')}.`
    // remaining params are ASCII text after the domain
    const params = binary.slice(pos).toString()

    return new SVCB({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'SVCB',
      priority: priority,
      'target name': targetName,
      params: params,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('priority')) +
        packDomainName(this.get('target name')) +
        escapeOctal(dataRe, this.get('params')),
    )
  }
}

class TLSA extends RR {
  static typeName = 'TLSA'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCertificateUsage(val) {
    if (!this.getCertificateUsageOptions().has(val)) this.throwHelp(`TLSA: certificate usage invalid`)

    this.set('certificate usage', val)
  }

  getCertificateUsageOptions() {
    return new Map([
      [0, 'CA certificate'],
      [1, 'an end entity certificate'],
      [2, 'the trust anchor'],
      [3, 'domain-issued certificate'],
    ])
  }

  setSelector(val) {
    if (!this.getSelectorOptions().has(val)) this.throwHelp(`TLSA: selector invalid`)

    this.set('selector', val)
  }

  getSelectorOptions() {
    return new Map([
      [0, 'Full certificate'],
      [1, 'SubjectPublicKeyInfo'],
    ])
  }

  setMatchingType(val) {
    if (!this.getMatchingTypeOptions().has(val)) this.throwHelp(`TLSA: matching type`)

    this.set('matching type', val)
  }

  getMatchingTypeOptions() {
    return new Map([
      [0, 'Exact match'],
      [1, 'SHA-256 hash'],
      [2, 'SHA-512 hash'],
    ])
  }

  setCertificateAssociationData(val) {
    this.set('certificate association data', val)
  }

  getDescription() {
    return 'TLSA certificate association'
  }

  getTags() {
    return ['security']
  }

  getRdataFields(arg) {
    return ['certificate usage', 'selector', 'matching type', 'certificate association data']
  }

  getRFCs() {
    return [6698, 7671]
  }

  getTypeId() {
    return 52
  }

  getCanonical() {
    return {
      owner: '_443._tcp.www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'TLSA',
      'certificate usage': 3,
      selector: 1,
      'matching type': 1,
      'certificate association data': 'ABCDEF...',
    }
  }

  getQuotedFields() {
    return []
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  TLSA, usage, selector, match, data
    const regex =
      /^(?<owner>\S+)\s+(?<ttl>\d{1,10})\s+(?<cls>IN)\s+(?<type>TLSA)\s+(?<usage>\d+)\s+(?<selector>\d+)\s+(?<matchtype>\d+)\s+(?<cad>\S.*)$/i
    const match = bindline.trim().match(regex)
    if (!match) this.throwHelp(`unable to parse TLSA: ${bindline}`)
    const { owner, ttl, cls, type, usage, selector, matchtype, cad } = match.groups

    return new TLSA({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      class: cls.toUpperCase(),
      type: type.toUpperCase(),
      'certificate usage': parseInt(usage, 10),
      selector: parseInt(selector, 10),
      'matching type': parseInt(matchtype, 10),
      'certificate association data': cad.trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 52) this.throwHelp('TLSA fromTinydns, invalid n')

    const bytes = Buffer.from(octalToChar(rdata), 'binary')

    return new TLSA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'TLSA',
      'certificate usage': bytes.readUInt8(0),
      selector: bytes.readUInt8(1),
      'matching type': bytes.readUInt8(2),
      'certificate association data': bytes.slice(3).toString(),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      UInt8toOctal(this.get('certificate usage')) +
        UInt8toOctal(this.get('selector')) +
        UInt8toOctal(this.get('matching type')) +
        escapeOctal(dataRe, this.get('certificate association data')),
    )
  }
}

class TSIG extends RR {
  static typeName = 'TSIG'
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/

  getDescription() {
    return 'Transaction Signature'
  }

  getRdataFields(arg) {
    return ['algorithm name', 'time signed', 'fudge', 'mac', 'original id', 'error', 'other']
  }

  getRFCs() {
    return [2845, 8945]
  }

  getTypeId() {
    return 250
  }

  getCanonical() {
    return {
      owner: 'test.example.',
      ttl: 0,
      class: 'ANY',
      type: 'TSIG',
      'algorithm name': 'hmac-sha256.',
      'time signed': 1620650000,
      fudge: 300,
      mac: 'ABCDEF...',
      'original id': 12345,
      error: 0,
      other: '',
    }
  }

  setClass(t) {
    if (t !== 'ANY') this.throwHelp('TSIG: Class is required to be ANY')
    this.set('class', t)
  }

  setTtl(t) {
    if (t !== 0) this.throwHelp('TSIG: TTL is required to be 0')
    this.set('ttl', t)
  }

  setAlgorithmName(val) {
    if (!val) this.throwHelp(`TSIG: 'algorithm name' is required`)
    this.set('algorithm name', val)
  }

  setTimeSigned(val) {
    // a 48-bit unsigned integer, as seconds since the UNIX epoch
    if (val === undefined) this.throwHelp(`TSIG: 'time signed' is required`)
    this.set('time signed', val)
  }

  setFudge(val) {
    // 16-bit unsigned
    this.is16bitInt('TSIG', 'fudge', val)
    this.set('fudge', val)
  }

  setMac(val) {
    this.set('mac', val ?? '')
  }

  setOriginalId(val) {
    this.is16bitInt('TSIG', 'original id', val)
    this.set('original id', val)
  }

  setError(val) {
    this.is16bitInt('TSIG', 'error', val)
    this.set('error', val)
  }

  setOther(val) {
    this.set('other', val ?? '')
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // owner ttl ANY TSIG alg time fudge mac_size mac original_id error other_len
    const parts = bindline.trimEnd().split('\t')
    const [owner, ttl, cls, type, alg, time, fudge, , mac, origId, error] = parts

    return new TSIG({
      owner,
      ttl: parseInt(ttl, 10),
      class: cls,
      type: type.toUpperCase(),
      'algorithm name': alg,
      'time signed': parseInt(time, 10),
      fudge: parseInt(fudge, 10),
      mac: mac || '',
      'original id': parseInt(origId, 10),
      error: parseInt(error, 10),
      other: '',
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')

    const algUnpacked = unpackDomainName(rdata)
    const algBinaryLen = algUnpacked[2]

    const bytes = Buffer.from(octalToChar(rdata), 'binary')
    let bpos = algBinaryLen

    const timeSigned = bytes.readUInt32BE(bpos)
    bpos += 4
    const fudge = bytes.readUInt16BE(bpos)
    bpos += 2
    const macSize = bytes.readUInt16BE(bpos)
    bpos += 2
    const mac = macSize > 0 ? bytes.slice(bpos, bpos + macSize).toString('hex') : ''
    bpos += macSize
    const originalId = bytes.readUInt16BE(bpos)
    bpos += 2
    const error = bytes.readUInt16BE(bpos)
    bpos += 2
    const other = bpos < bytes.length ? bytes.slice(bpos).toString() : ''

    return new TSIG({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      class: 'ANY',
      type: 'TSIG',
      'algorithm name': algUnpacked[0],
      'time signed': timeSigned,
      fudge,
      mac,
      'original id': originalId,
      error,
      other,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    const mac = this.get('mac') ?? ''
    const macSize = mac.length > 0 ? mac.length : ''
    const other = this.get('other') ?? ''
    const otherLen = other.length > 0 ? other.length : 0
    return (
      [
        this.getFQDN('owner', zone_opts),
        this.get('ttl'),
        this.get('class'),
        this.get('type'),
        this.get('algorithm name'),
        this.get('time signed'),
        this.get('fudge'),
        macSize,
        mac,
        this.get('original id'),
        this.get('error'),
        otherLen,
      ].join('\t') + '\n'
    )
  }

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    const alg = this.get('algorithm name') || ''

    return this.getTinydnsGeneric(
      packDomainName(alg) +
        UInt32toOctal(this.get('time signed') ?? 0) +
        UInt16toOctal(this.get('fudge')) +
        UInt16toOctal(this.get('mac size') ?? 0) +
        (this.get('mac size') > 0 ? escapeOctal(dataRe, this.get('mac')) : '') +
        UInt16toOctal(this.get('original id') ?? 0) +
        UInt16toOctal(this.get('error') ?? 0) +
        (this.get('other').length > 0 ? escapeOctal(dataRe, this.get('other')) : ''),
    )
  }
}

class URI extends RR {
  static typeName = 'URI'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('URI', 'priority', val)

    this.set('priority', val)
  }

  setWeight(val) {
    this.is16bitInt('URI', 'weight', val)

    this.set('weight', val)
  }

  setTarget(val) {
    if (!val) this.throwHelp(`URI: target is required`)

    this.set('target', val)
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // URI via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 256) this.throwHelp('URI fromTinydns, invalid n')

    return new URI({
      type: 'URI',
      owner: this.fullyQualify(fqdn),
      priority: octalToUInt16(rdata.slice(0, 8)),
      weight: octalToUInt16(rdata.slice(8, 16)),
      target: octalToChar(rdata.slice(16)),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  URI  priority, weight, target
    const [owner, ttl, c, type, priority, weight, target] = bindline.split(/\s+/)
    return new URI({
      class: c,
      type: type,
      owner,
      priority: parseInt(priority, 10),
      weight: parseInt(weight, 10),
      target: target.replace(/^"|"$/g, ''),
      ttl: parseInt(ttl, 10),
    })
  }

  /******  MISC   *******/
  getDescription() {
    return 'URI'
  }

  getRdataFields(arg) {
    return ['priority', 'weight', 'target']
  }

  getRFCs() {
    return [7553]
  }

  getTypeId() {
    return 256
  }

  getCanonical() {
    return {
      owner: 'www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'URI',
      priority: 10,
      weight: 10,
      target: 'http://www.example.com/',
    }
  }

  getQuotedFields() {
    return ['target']
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    let rdata = ''

    for (const e of ['priority', 'weight']) {
      rdata += UInt16toOctal(this.get(e))
    }

    rdata += escapeOctal(dataRe, this.get('target'))
    return this.getTinydnsGeneric(rdata)
  }
}

class WKS extends RR {
  static typeName = 'WKS'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('WKS: address is required')
    if (!this.isIPv4(val)) this.throwHelp('WKS address must be IPv4')
    this.set('address', val)
  }

  setProtocol(val) {
    if (!val) this.throwHelp('WKS: protocol is required')
    const upper = typeof val === 'string' ? val.toUpperCase() : val
    if (!['TCP', 'UDP', 6, 17].includes(upper)) this.throwHelp('WKS protocol must be TCP or UDP')
    this.set('protocol', upper)
  }

  setBitMap(val) {
    this.set('bit map', val ?? '')
  }

  getDescription() {
    return 'Well Known Service'
  }

  getTags() {
    return ['obsolete']
  }

  getRdataFields(arg) {
    return ['address', 'protocol', 'bit map']
  }

  getRFCs() {
    return [883, 1035]
  }

  getTypeId() {
    return 11
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'WKS',
      address: '192.0.2.1',
      protocol: 'TCP',
      'bit map': 'ftp smtp',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  WKS 192.168.1.1 TCP ftp smtp
    const parts = bindline.split(/\s+/)
    const [owner, ttl, c, type, address, protocol] = parts
    return new WKS({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      address,
      protocol,
      'bit map': parts.slice(6).join(' ').trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')

    const binary = Buffer.from(octalToChar(rdata), 'binary')
    const address = [binary.readUInt8(0), binary.readUInt8(1), binary.readUInt8(2), binary.readUInt8(3)].join(
      '.',
    )
    const protoNum = binary.readUInt8(4)
    const protoMap = { 6: 'TCP', 17: 'UDP' }
    const protocol = protoMap[protoNum] ?? protoNum
    const bitmap = binary.slice(5).toString()

    return new WKS({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'WKS',
      address,
      protocol,
      'bit map': bitmap,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    const protoMap = { TCP: 6, UDP: 17, 6: 6, 17: 17 }
    const protoNum = protoMap[this.get('protocol')]

    return this.getTinydnsGeneric(
      ipv4toOctal(this.get('address')) + UInt8toOctal(protoNum) + escapeOctal(dataRe, this.get('bit map')),
    )
  }
}

const typeMap = {}

for (const c of [
  A,
  AAAA,
  APL,
  CAA,
  CERT,
  CNAME,
  DHCID,
  DNAME,
  DNSKEY,
  DS,
  HINFO,
  HIP,
  HTTPS,
  IPSECKEY,
  KEY,
  KX,
  LOC,
  MX,
  NAPTR,
  NS,
  NSEC,
  NSEC3,
  NSEC3PARAM,
  NXT,
  OPENPGPKEY,
  PTR,
  RP,
  RRSIG,
  SIG,
  SMIMEA,
  SSHFP,
  SOA,
  SPF,
  SRV,
  SVCB,
  TLSA,
  TSIG,
  TXT,
  URI,
  WKS,
]) {
  const id = new c(null).getTypeId()
  typeMap[id] = c.typeName
  typeMap[c.typeName] = id
}

export {
  A,
  AAAA,
  APL,
  CAA,
  CERT,
  CNAME,
  DHCID,
  DNAME,
  DNSKEY,
  DS,
  HINFO,
  HIP,
  HTTPS,
  IPSECKEY,
  KEY,
  KX,
  LOC,
  MX,
  NAPTR,
  NS,
  NSEC,
  NSEC3,
  NSEC3PARAM,
  NXT,
  OPENPGPKEY,
  PTR,
  RP,
  RRSIG,
  SIG,
  SMIMEA,
  SOA,
  SPF,
  SRV,
  SSHFP,
  SVCB,
  TLSA,
  TSIG,
  TXT,
  URI,
  WKS,
  RR as default,
  typeMap,
}
