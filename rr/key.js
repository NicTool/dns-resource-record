import RR from '../rr.js'

export default class KEY extends RR {
  static typeName = 'KEY'
  static typeId = 25
  static RFCs = [2535, 3445, 4034, 6840]
  static rdataFields = [
    ['flags', 'u16'],
    ['protocol', 'u8'],
    ['algorithm', 'u8'],
    ['publickey', 'base64'],
  ]
  static tags = ['obsolete']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags(val) {
    // a 2 octet Flags Field
    this.is16bitInt('KEY', 'flags', val)

    this.set('flags', val)
  }

  setProtocol(val) {
    // 1 octet
    this.is8bitInt('KEY', 'protocol', val)

    this.set('protocol', val)
  }

  setAlgorithm(val) {
    // 1 octet

    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`KEY: algorithm invalid`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [253, ''],
      [254, ''],
    ])
  }

  setPublickey(val) {
    if (!val) this.throwHelp(`KEY: publickey is required`)
    const key = val.replace(/[\s()]/g, '')
    this.isBase64('KEY', 'publickey', key)
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
      type: 'KEY',
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
