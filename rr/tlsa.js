import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import * as BINARY from '../lib/binary.js'

export default class TLSA extends RR {
  static typeName = 'TLSA'
  static typeId = 52
  static RFCs = [6698, 7671]
  static rdataFields = [
    ['certificate usage', 'u8'],
    ['selector', 'u8'],
    ['matching type', 'u8'],
    ['certificate association data', 'hex'],
  ]
  static tags = ['security']

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

    const bytes = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))

    return new TLSA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'TLSA',
      'certificate usage': bytes[0],
      selector: bytes[1],
      'matching type': bytes[2],
      'certificate association data': BINARY.bytesToHex(bytes.subarray(3)),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      TINYDNS.UInt8toOctal(this.get('certificate usage')) +
        TINYDNS.UInt8toOctal(this.get('selector')) +
        TINYDNS.UInt8toOctal(this.get('matching type')) +
        TINYDNS.packHex(this.get('certificate association data').replace(/[\s()]/g, '')),
    )
  }

  getWireRdata() {
    const cadBytes = BINARY.hexToBytes(this.get('certificate association data').replace(/[\s()]/g, ''))
    const bytes = new Uint8Array(3 + cadBytes.length)
    bytes[0] = this.get('certificate usage')
    bytes[1] = this.get('selector')
    bytes[2] = this.get('matching type')
    bytes.set(cadBytes, 3)
    return bytes
  }
}
