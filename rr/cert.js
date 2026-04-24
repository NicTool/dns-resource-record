import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import * as BINARY from '../lib/binary.js'

export default class CERT extends RR {
  static typeName = 'CERT'
  static typeId = 37
  static RFCs = [2538, 4398]
  static rdataFields = [
    ['cert type', 'certtype'],
    ['key tag', 'u16'],
    ['algorithm', 'u8'],
    ['certificate', 'base64'],
  ]

  static CERT_TYPES = {
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

  static CERT_TYPES_REVERSE = Object.fromEntries(Object.entries(CERT.CERT_TYPES).map(([k, v]) => [v, k]))

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
    if (typeof val === 'string' && !/^[0-9]+$/.test(val)) {
      if (!Object.hasOwn(CERT.CERT_TYPES, val)) {
        this.throwHelp(`CERT: unknown cert type mnemonic: ${val}`)
      }
    } else {
      this.is16bitInt('CERT', 'cert type', val)
    }
    this.set('cert type', val)
  }

  getCertTypeValue(val) {
    if (typeof val === 'number') return val
    if (/^[0-9]+$/.test(val)) return parseInt(val, 10)
    if (Object.hasOwn(CERT.CERT_TYPES, val)) return CERT.CERT_TYPES[val]
    this.throwHelp(`CERT: unknown cert type mnemonic: ${val}`)
  }

  setCertificate(val) {
    // certificate/CRL portion is represented in base 64 [16] and may be
    // divided into any number of white-space-separated substrings
    if (val === undefined || val === null || val === '') {
      this.throwHelp('certificate is required and cannot be empty')
    }
    this.isBase64('CERT', 'certificate', val.replace(/[\s()]/g, ''))
    this.set('certificate', val)
  }

  getDescription() {
    return 'Certificate'
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
      certificate: 'AQIDBA==',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline)
    if (typeId != this.getTypeId()) this.throwHelp('CERT fromTinydns, invalid n')

    const bytes = TINYDNS.octalRdataToBytes(rdata)
    const typeNum = (bytes[0] << 8) | bytes[1]

    const certType = CERT.CERT_TYPES_REVERSE[typeNum] ?? typeNum

    return new CERT({
      owner,
      ttl,
      type: 'CERT',
      'cert type': certType,
      'key tag': (bytes[2] << 8) | bytes[3],
      algorithm: bytes[4],
      certificate: BINARY.bytesToBase64(bytes.subarray(5)),
      timestamp,
      location,
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
    return this.getTinydnsGeneric(
      TINYDNS.UInt16toOctal(this.getCertTypeValue(this.get('cert type'))) +
        TINYDNS.UInt16toOctal(this.get('key tag')) +
        TINYDNS.UInt8toOctal(this.get('algorithm')) +
        TINYDNS.base64toOctal(this.get('certificate').replace(/[\s()]/g, '')),
    )
  }

  getWireRdata() {
    const certBytes = BINARY.base64ToBytes(this.get('certificate').replace(/[\s()]/g, ''))
    const bytes = new Uint8Array(5 + certBytes.length)
    const dv = new DataView(bytes.buffer, bytes.byteOffset)
    dv.setUint16(0, this.getCertTypeValue(this.get('cert type')))
    dv.setUint16(2, this.get('key tag'))
    bytes[4] = this.get('algorithm')
    bytes.set(certBytes, 5)
    return bytes
  }
}
