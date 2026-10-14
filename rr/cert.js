import RR from '../rr.js'

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

  setKeyTag(val) {
    this.setTypedValue('u16', 'key tag', val)
  }

  setAlgorithm(val) {
    this.setTypedValue('u8', 'algorithm', val)
  }

  setCertificate(val) {
    // certificate/CRL portion is represented in base 64 [16] and may be
    // divided into any number of white-space-separated substrings
    if (val === undefined || val === null || val === '') {
      this.throwHelp('certificate is required and cannot be empty')
    }
    this.isString('CERT', 'certificate', val)
    const certificate = val.replace(/[\s()]/g, '')
    this.isBase64('CERT', 'certificate', certificate)
    this.set('certificate', certificate)
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

  /******  EXPORTERS   *******/
}
