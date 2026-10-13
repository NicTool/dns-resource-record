import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import { escapeCharString } from '../lib/bind.js'
import { quoteCharString } from '../lib/maradns.js'

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
    if (tinyline[0] !== "'") return this.fromTinydnsWire({ tinyline })

    // 'fqdn:s:ttl:timestamp:lo, which tinydns-data stores as strings of at most 127 bytes
    const [fqdn, s, ttl, ts, loc] = tinyline.slice(1).split(':')
    const bytes = TINYDNS.octalRdataToBytes(s)
    const utf8 = new TextDecoder('utf-8', { fatal: true })
    const strings = []
    for (let i = 0; i < bytes.length; i += TINYDNS_TXT_CHUNK) {
      strings.push(utf8.decode(bytes.subarray(i, i + TINYDNS_TXT_CHUNK)))
    }

    return new this.constructor({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'TXT',
      data: strings.length > 1 ? strings : (strings[0] ?? ''),
      timestamp: ts,
      location: loc?.trim() || '',
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t"${asQuotedStrings(this.get('data'))}"\n`
  }

  toMaraDNS() {
    this.assertClassIN('MaraDNS')
    // csv2_txt(5): an unquoted ';' separates chunks.
    const data = asQuotedStrings(this.get('data'), { quote: quoteCharString, delimiter: ';' })
    return `${this.get('owner')}\t+${this.get('ttl')}\t${this.get('type')}\t${data} ~\n`
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

  // A ' line can hold only one string of 1 to 127 bytes, since tinydns-data
  // splits longer text at 127; anything else takes the generic form.
  toTinydns() {
    const data = this.get('data')
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : null
    if (!this.constructor.tinydnsType || !bytes?.length || bytes.length > TINYDNS_TXT_CHUNK)
      return this.getTinydnsGeneric(TINYDNS.bytesToTinydnsText(this.getWireRdata()))
    return `'${this.getTinyFQDN('owner')}:${TINYDNS.bytesToTinydnsText(bytes)}:${this.getTinydnsPostamble()}\n`
  }
}

// RFC 1035 character-strings are 255 bytes max. The limit counts wire bytes,
// so chunk the unescaped value by UTF-8 bytes and escape each chunk afterwards.
function asQuotedStrings(data, { quote = escapeCharString, delimiter = '" "' } = {}) {
  const enc = new TextEncoder()

  if (Array.isArray(data)) {
    const anyTooLong = data.some((s) => enc.encode(s).length > 255)
    if (!anyTooLong) return data.map(quote).join(delimiter)
    return chunkByBytes(data.join(''), 255).map(quote).join(delimiter)
  }

  if (enc.encode(data).length <= 255) return quote(data)
  return chunkByBytes(data, 255).map(quote).join(delimiter)
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

const TINYDNS_TXT_CHUNK = 127
