import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class TXT extends RR {
  static typeName = 'TXT'
  static typeId = 16
  static RFCs = [1035, 4408, 7208, 6376]
  static tinydnsType = "'"
  static rdataFields = [['data', 'charstrs']]
  static tags = ['common']

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
    // Walk RFC 1035 §3.3.14 len-prefixed <character-string> segments.
    const parts = []
    let pos = 0
    while (pos < rdata.length) {
      const len = rdata.charCodeAt(pos)
      pos += 1
      if (pos + len > rdata.length) {
        this.throwHelp('TXT fromTinydnsGeneric: truncated character-string in rdata')
      }
      parts.push(rdata.slice(pos, pos + len))
      pos += len
    }
    const data = parts.length > 1 ? parts : (parts[0] ?? '')
    return [fqdn, data, ttl, ts, loc]
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
    // RFC 1035 §3.3.14: TXT rdata is one or more <character-string>s, each up
    // to 255 bytes. An array preserves explicit boundaries between strings;
    // each element MUST be <= 255 UTF-8 bytes, otherwise we would silently
    // split it and the boundary the caller asked us to preserve would be lost.
    // A single string is auto-chunked at 255-byte UTF-8 boundaries.
    const data = this.get('data')
    if (Array.isArray(data)) {
      const enc = new TextEncoder()
      const buffers = data.map((s, i) => {
        if (enc.encode(s).length > 255) {
          this.throwHelp(
            `TXT: array element ${i} exceeds 255 bytes; split it yourself or pass a single string to auto-chunk`,
          )
        }
        return packStringWire(s)
      })
      const total = buffers.reduce((n, b) => n + b.length, 0)
      const out = new Uint8Array(total)
      let off = 0
      for (const b of buffers) {
        out.set(b, off)
        off += b.length
      }
      return out
    }
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
