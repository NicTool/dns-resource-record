import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import * as BINARY from '../lib/binary.js'

// RFC 6698 §2.1.3: matching types 1 and 2 are SHA-256 and SHA-512 digests.
const DIGEST_BYTES = { 1: 32, 2: 64 }

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
    const data = this.get('certificate association data')
    if (data !== undefined) this.isHexDigest('certificate association data', data, DIGEST_BYTES[val])
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
    this.isHexDigest('certificate association data', val, DIGEST_BYTES[this.get('matching type')])
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
      'certificate association data': 'D2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline)
    if (typeId != this.getTypeId()) this.throwHelp('TLSA fromTinydns, invalid n')

    const bytes = TINYDNS.octalRdataToBytes(rdata)

    return new TLSA({
      owner,
      ttl,
      type: 'TLSA',
      'certificate usage': bytes[0],
      selector: bytes[1],
      'matching type': bytes[2],
      'certificate association data': BINARY.bytesToHex(bytes.subarray(3)),
      timestamp,
      location,
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
