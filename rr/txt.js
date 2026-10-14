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

  /****** Resource record specific setters   *******/
  // An array keeps the character-string boundaries it was given (RFC 1035
  // §3.3.14), so each element must already fit in 255 bytes.
  setData(val) {
    const typeName = this.constructor.typeName
    const strings = Array.isArray(val) ? val : [val]
    if (!strings.length || strings.some((s) => typeof s !== 'string'))
      this.throwHelp(`${typeName}: data must be a string or a non-empty array of strings`)
    if (Array.isArray(val) && val.some((s) => new TextEncoder().encode(s).length > 255))
      this.throwHelp(
        `${typeName}: each string in a data array must be <=255 bytes; pass one string to split it`,
      )
    this.set('data', val)
  }

  // A single string is split into 255-byte character-strings on UTF-8 boundaries.
  getCharStrings() {
    const data = this.get('data')
    if (Array.isArray(data)) return data
    return data === '' ? [''] : chunkByBytes(data, 255)
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
    const bytes = TINYDNS.octalRdataToBytes(s ?? '')
    const utf8 = new TextDecoder('utf-8', { fatal: true })
    const strings = []
    for (let i = 0; i < bytes.length; i += TINYDNS_TXT_CHUNK) {
      strings.push(utf8.decode(bytes.subarray(i, i + TINYDNS_TXT_CHUNK)))
    }

    return new this.constructor({
      owner: this.fromTinyFQDN(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'TXT',
      data: strings.length > 1 ? strings : (strings[0] ?? ''),
      timestamp: ts,
      location: loc?.trim() || '',
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t"${this.getCharStrings().map(escapeCharString).join('" "')}"\n`
  }

  toMaraDNS() {
    this.assertClassIN('MaraDNS')
    // csv2_txt(5): an unquoted ';' separates chunks.
    const data = this.getCharStrings().map(quoteCharString).join(';')
    return `${this.get('owner')}\t+${this.get('ttl')}\t${this.get('type')}\t${data} ~\n`
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

const TINYDNS_TXT_CHUNK = 127
