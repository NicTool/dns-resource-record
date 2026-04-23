import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import { DNS_TYPE_IDS } from '../lib/binary.js'

export default class NSEC extends RR {
  static typeName = 'NSEC'
  static typeId = 47
  static RFCs = [4034]
  static rdataFields = ['next domain', 'type bit maps']
  static tags = ['dnssec']

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
    const binaryRdata = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))
    const [nextDomain, _escapedLen, binaryLen] = TINYDNS.unpackDomainName(rdata)

    return new NSEC({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'NSEC',
      'next domain': nextDomain,
      'type bit maps': new TextDecoder().decode(binaryRdata.subarray(binaryLen)),
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
      'type bit maps': bindline.split(/\s+/).slice(5).filter(removeParens).join(' ').trim(),
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const { fqdn: nextDomain, end } = this.wireUnpackDomain(rdata, 0)
    const typeBitMaps = nsecBitmapToTypes(rdata.subarray(end))
    return new NSEC({
      owner,
      ttl,
      class: cls,
      type: 'NSEC',
      'next domain': nextDomain,
      'type bit maps': typeBitMaps,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.packDomainName(this.get('next domain')) +
        TINYDNS.escapeOctal(dataRe, this.get('type bit maps')),
    )
  }

  getWireRdata() {
    const nameBytes = this.wirePackDomain(this.get('next domain'))
    const bitmapBytes = typesToNsecBitmap(this.get('type bit maps'))
    const result = new Uint8Array(nameBytes.length + bitmapBytes.length)
    result.set(nameBytes)
    result.set(bitmapBytes, nameBytes.length)
    return result
  }
}

const removeParens = (a) => !['(', ')'].includes(a)

function nsecBitmapToTypes(bitmap) {
  const DNS_TYPE_NAMES = Object.fromEntries(Object.entries(DNS_TYPE_IDS).map(([k, v]) => [v, k]))
  const types = []
  let pos = 0
  while (pos + 2 <= bitmap.length) {
    const windowNum = bitmap[pos]
    const bitmapLen = bitmap[pos + 1]
    pos += 2
    for (let i = 0; i < bitmapLen; i++) {
      const byte = bitmap[pos + i]
      for (let bit = 0; bit < 8; bit++) {
        if (byte & (0x80 >> bit)) {
          const typeId = windowNum * 256 + i * 8 + bit
          types.push(DNS_TYPE_NAMES[typeId] ?? `TYPE${typeId}`)
        }
      }
    }
    pos += bitmapLen
  }
  return types.join(' ')
}

function typesToNsecBitmap(typeNamesStr) {
  const typeIds = typeNamesStr
    .trim()
    .split(/\s+/)
    .map((t) => {
      if (/^TYPE\d+$/i.test(t)) return parseInt(t.slice(4), 10)
      return DNS_TYPE_IDS[t.toUpperCase()]
    })
    .filter((id) => id !== undefined && id >= 0)

  const windows = new Map()
  for (const id of typeIds) {
    const w = Math.floor(id / 256)
    if (!windows.has(w)) windows.set(w, [])
    windows.get(w).push(id % 256)
  }

  const blocks = []
  for (const [wNum, bits] of [...windows.entries()].sort((a, b) => a[0] - b[0])) {
    const maxBit = Math.max(...bits)
    const bitmapLen = Math.floor(maxBit / 8) + 1
    const bitmap = new Uint8Array(bitmapLen)
    for (const b of bits) bitmap[Math.floor(b / 8)] |= 0x80 >> (b % 8)
    blocks.push(new Uint8Array([wNum, bitmapLen, ...bitmap]))
  }

  const total = blocks.reduce((s, b) => s + b.length, 0)
  const result = new Uint8Array(total)
  let pos = 0
  for (const b of blocks) {
    result.set(b, pos)
    pos += b.length
  }
  return result
}
