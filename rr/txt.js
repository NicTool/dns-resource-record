import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class TXT extends RR {
  static typeName = 'TXT'
  static tinydnsType = "'"
  static rdataFields = ['data']
  static quotedFields = ['data']

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
      rdata = TINYDNS.octalToChar(s)
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

    rdata = TINYDNS.octalToChar(rdata)
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

  fromWire({ owner, cls, ttl, rdata }) {
    let pos = 0
    const parts = []
    while (pos < rdata.length) {
      const len = rdata[pos++]
      parts.push(new TextDecoder().decode(rdata.subarray(pos, pos + len)))
      pos += len
    }
    return new this.constructor({
      owner,
      ttl,
      class: cls,
      type: this.constructor.typeName,
      data: parts.join(''),
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
    const rdata = TINYDNS.escapeOctal(new RegExp(/[\r\n\t:\\/]/, 'g'), data)
    return `'${this.getTinyFQDN('owner')}:${rdata}:${this.getTinydnsPostamble()}\n`
  }
}

function asQuotedStrings(data) {
  // RFC 1035 character-strings are 255 bytes max; chunk by UTF-8 bytes,
  // not JS chars, so non-ASCII TXT data doesn't overflow the 255-byte limit.
  const enc = new TextEncoder()

  if (Array.isArray(data)) {
    const anyTooLong = data.some((s) => enc.encode(s).length > 255)
    if (!anyTooLong) return data.join('" "')
    return chunkByBytes(data.join(''), 255).join('" "')
  }

  if (enc.encode(data).length <= 255) return data
  return chunkByBytes(data, 255).join('" "')
}

function chunkByBytes(str, maxBytes) {
  const bytes = new TextEncoder().encode(str)
  const dec = new TextDecoder()
  const chunks = []
  let start = 0
  while (start < bytes.length) {
    let end = Math.min(start + maxBytes, bytes.length)
    // back up to a UTF-8 codepoint boundary so decode() returns whole chars
    while (end < bytes.length && (bytes[end] & 0xc0) === 0x80) end--
    chunks.push(dec.decode(bytes.subarray(start, end)))
    start = end
  }
  return chunks
}

function packStringWire(str) {
  const encoded = new TextEncoder().encode(str)
  if (encoded.length === 0) return new Uint8Array([0])

  const chunks = []
  for (let i = 0; i < encoded.length; i += 255) chunks.push(encoded.subarray(i, i + 255))

  const buf = new Uint8Array(encoded.length + chunks.length)
  let offset = 0
  for (const chunk of chunks) {
    buf[offset++] = chunk.length
    buf.set(chunk, offset)
    offset += chunk.length
  }
  return buf
}
