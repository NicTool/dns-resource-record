import RR from '../rr.js'

// RFC 4255 §3.1.3, RFC 6594: SHA-1 and SHA-256 fingerprints.
const FINGERPRINT_BYTES = { 1: 20, 2: 32 }

export default class SSHFP extends RR {
  static typeName = 'SSHFP'
  static typeId = 44
  static RFCs = [4255, 7479, 8709]
  static rdataFields = [
    ['algorithm', 'u8'],
    ['fptype', 'u8'],
    ['fingerprint', 'hex'],
  ]
  static tags = ['security']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAlgorithm(val) {
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`SSHFP: algorithm invalid`)
    this.setTypedValue('u8', 'algorithm', val)
  }

  setFptype(val) {
    if (!this.getFptypeOptions().has(val)) this.throwHelp(`SSHFP: fptype invalid`)
    if (this.get('fingerprint') !== undefined)
      this.isHexDigest('fingerprint', this.get('fingerprint'), FINGERPRINT_BYTES[val])
    this.setTypedValue('u8', 'fptype', val)
  }

  setFingerprint(val) {
    this.isHexDigest('fingerprint', val, FINGERPRINT_BYTES[this.get('fptype')])
    this.set('fingerprint', val.toUpperCase())
  }

  getAlgorithmOptions() {
    return new Map([
      [0, 'reserved'],
      [1, 'RSA'],
      [2, 'DSA'],
      [3, 'ECDSA'],
      [4, 'Ed25519'],
      [6, 'Ed448'],
    ])
  }

  getFptypeOptions() {
    return new Map([
      [0, 'reserved'],
      [1, 'SHA-1'],
      [2, 'SHA-256'],
    ])
  }

  getDescription() {
    return 'Secure Shell Key Fingerprints'
  }

  getCanonical() {
    return {
      owner: 'mail.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SSHFP',
      algorithm: 2,
      fptype: 1,
      fingerprint: '123456789abcdef6789abcdf6789abdf6789abcd',
    }
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/
}
