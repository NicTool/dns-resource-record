import RR from '../rr.js'

// RFC 4034 §5.1.4, RFC 4509, RFC 6605: SHA-1, SHA-256 and SHA-384 digests.
const DIGEST_BYTES = { 1: 20, 2: 32, 4: 48 }

export default class DS extends RR {
  static typeName = 'DS'
  static typeId = 43
  static RFCs = [4034, 4509, 9619]
  static rdataFields = [
    ['key tag', 'u16'],
    ['algorithm', 'u8'],
    ['digest type', 'u8'],
    ['digest', 'hex'],
  ]
  static tags = ['dnssec']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setKeyTag(val) {
    this.setTypedValue('u16', 'key tag', val)
  }

  setDigest(val) {
    this.isHexDigest('digest', val, DIGEST_BYTES[this.get('digest type')])
    this.set('digest', val.toUpperCase())
  }

  setAlgorithm(val) {
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`DS: algorithm invalid`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    // IANA DNSSEC Algorithm Numbers
    // https://www.iana.org/assignments/dns-sec-alg-numbers/
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [6, 'DSA-NSEC3-SHA1'],
      [7, 'RSASHA1-NSEC3-SHA1'],
      [8, 'RSA/SHA-256'],
      [10, 'RSA/SHA-512'],
      [13, 'ECDSA P-256/SHA-256'],
      [14, 'ECDSA P-384/SHA-384'],
      [15, 'Ed25519'],
      [16, 'Ed448'],
      [253, ''],
      [254, ''],
    ])
  }

  setDigestType(val) {
    if (!Object.hasOwn(DIGEST_BYTES, val)) this.throwHelp(`DS: digest type invalid`)
    if (this.get('digest') !== undefined) this.isHexDigest('digest', this.get('digest'), DIGEST_BYTES[val])
    this.set('digest type', val)
  }

  getDescription() {
    return 'Delegation Signer'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DS',
      'key tag': 60485,
      algorithm: 5,
      'digest type': 1,
      digest: '2BB183AF5F22588179A53B0A98631FAD1A292118',
    }
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/
}
