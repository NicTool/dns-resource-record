import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import { DNS_TYPE_IDS } from '../lib/binary.js'

export default class NXT extends RR {
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
    return ['obsolete']
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

    const binaryRdata = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))
    const [nextDomain, _escapedLen, binaryLen] = TINYDNS.unpackDomainName(rdata)

    return new NXT({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'NXT',
      'next domain': nextDomain,
      'type bit map': new TextDecoder().decode(binaryRdata.subarray(binaryLen)),
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

  fromWire({ owner, cls, ttl, rdata }) {
    const { fqdn: nextDomain, end } = this.wireUnpackDomain(rdata, 0)
    const typeBitMap = nxtBitmapToTypes(rdata.subarray(end))
    return new NXT({
      owner,
      ttl,
      class: cls,
      type: 'NXT',
      'next domain': nextDomain,
      'type bit map': typeBitMap,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.packDomainName(this.get('next domain')) + TINYDNS.escapeOctal(dataRe, this.get('type bit map')),
    )
  }

  getWireRdata() {
    const nameBytes = this.wirePackDomain(this.get('next domain'))
    const bitmapBytes = typesToNxtBitmap(this.get('type bit map'))
    const result = new Uint8Array(nameBytes.length + bitmapBytes.length)
    result.set(nameBytes)
    result.set(bitmapBytes, nameBytes.length)
    return result
  }
}

const removeParens = (a) => !['(', ')'].includes(a)

function nxtBitmapToTypes(bitmap) {
  const DNS_TYPE_NAMES = Object.fromEntries(Object.entries(DNS_TYPE_IDS).map(([k, v]) => [v, k]))
  const types = []
  for (let i = 0; i < bitmap.length; i++) {
    const byte = bitmap[i]
    for (let bit = 0; bit < 8; bit++) {
      if (byte & (0x80 >> bit)) {
        const typeId = i * 8 + bit
        types.push(DNS_TYPE_NAMES[typeId] ?? `TYPE${typeId}`)
      }
    }
  }
  return types.join(' ')
}

function typesToNxtBitmap(typeNamesStr) {
  const bitmap = new Uint8Array(16)
  for (const name of typeNamesStr.trim().split(/\s+/)) {
    const id = /^TYPE\d+$/i.test(name) ? parseInt(name.slice(4), 10) : DNS_TYPE_IDS[name.toUpperCase()]
    if (id !== undefined && id < 128) bitmap[Math.floor(id / 8)] |= 0x80 >> (id % 8)
  }
  let len = bitmap.length
  while (len > 0 && bitmap[len - 1] === 0) len--
  return bitmap.slice(0, len)
}
