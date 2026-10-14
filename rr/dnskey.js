import RR from '../rr.js'

export default class DNSKEY extends RR {
  static typeName = 'DNSKEY'
  static typeId = 48
  static RFCs = [4034, 6014, 8624, 9619, 9905]
  static rdataFields = [
    ['flags', 'u16'],
    ['protocol', 'u8'],
    ['algorithm', 'u8'],
    ['publickey', 'base64'],
  ]
  static tags = ['dnssec']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags(val) {
    // a 2 octet Flags Field
    this.is16bitInt('DNSKEY', 'flags', val)

    if (!this.getFlagsOptions().has(val)) {
      this.throwHelp(`DNSKEY: flags must be in the set: ${this.getFlagsOptions()}`)
    }

    this.set('flags', val)
  }

  // possible values are: 0, 256, and 257; RFC 4034
  getFlagsOptions() {
    return new Map([[0], [256], [257]])
  }

  setProtocol(val) {
    // 1 octet
    this.is8bitInt('DNSKEY', 'protocol', val)

    // The Protocol Field MUST be represented as an unsigned decimal integer with a value of 3.
    if (!this.getProtocolOptions().has(val)) this.throwHelp(`DNSKEY: protocol invalid`)

    this.set('protocol', val)
  }

  getProtocolOptions() {
    return new Map([[3]])
  }

  setAlgorithm(val) {
    // 1 octet
    this.is8bitInt('DNSKEY', 'algorithm', val)

    // https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    if (!this.getAlgorithmOptions().has(val)) console.error(`DNSKEY: algorithm (${val}) not recognized`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'RSA/MD5 (DEPRECATED)'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [6, 'DSA-NSEC3-SHA1'],
      [7, 'RSASHA1-NSEC3-SHA1'],
      [8, 'RSA/SHA-256'],
      [9, ''],
      [10, 'RSA/SHA-512'],
      [13, 'ECDSA Curve P-256 with SHA-256'],
      [14, 'ECDSA Curve P-384 with SHA-384'],
      [15, 'Ed25519'],
      [16, 'Ed448'],
      [253],
      [254],
    ])
  }

  setPublickey(val) {
    if (!val) this.throwHelp(`DNSKEY: publickey is required`)
    const key = val.replace(/[\s()]/g, '')
    this.isBase64('DNSKEY', 'publickey', key)
    this.set('publickey', key)
  }

  getDescription() {
    return 'DNS Public Key'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DNSKEY',
      flags: 256,
      protocol: 3,
      algorithm: 5,
      publickey:
        'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA==',
    }
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/
}
