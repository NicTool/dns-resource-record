import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class DNSKEY extends RR {
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
  getFlagsOptions () { return new Map([ [0], [256], [257] ]) }

  setProtocol(val) {
    // 1 octet
    this.is8bitInt('DNSKEY', 'protocol', val)

    // The Protocol Field MUST be represented as an unsigned decimal integer with a value of 3.
    if (!this.getProtocolOptions().has(val)) this.throwHelp(`DNSKEY: protocol invalid`)

    this.set('protocol', val)
  }

  getProtocolOptions () { return new Map([ [3] ]) }

  setAlgorithm(val) {
    // 1 octet
    this.is8bitInt('DNSKEY', 'algorithm', val)

    // https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    if (!this.getAlgorithmOptions().has(val))
      console.error(`DNSKEY: algorithm (${val}) not recognized`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions () { return new Map([
      [1, 'RSA/MD5 (DEPRECATED)' ],
      [2, 'DH' ],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1' ],
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

    this.set('publickey', val)
  }

  getDescription() {
    return 'DNS Public Key'
  }

  getRdataFields(arg) {
    return ['flags', 'protocol', 'algorithm', 'publickey']
  }

  getRFCs() {
    return [4034, 6014, 8624]
  }

  getTypeId() {
    return 48
  }

  /******  IMPORTERS   *******/

  fromBind(opts) {
    // test.example.com  3600  IN  DNSKEY Flags Protocol Algorithm PublicKey
    const match = opts.bindline.match(
      /^([^\s]+)\s+([0-9]+)\s+(\w+)\s+(\w+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+\s*(.*?)\s*$/,
    )
    if (!match) this.throwHelp(`unable to parse DNSKEY: ${opts.bindline}`)
    const [owner, ttl, c, type, flags, protocol, algorithm, publickey] =
      match.slice(1)

    return new DNSKEY({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      flags: parseInt(flags, 10),
      protocol: parseInt(protocol, 10),
      algorithm: parseInt(algorithm, 10),
      publickey: publickey,
    })
  }

  fromTinydns(opts) {
    const [fqdn, n, rdata, ttl, ts, loc] = opts.tinyline.substring(1).split(':')
    if (n != 48) this.throwHelp('DNSKEY fromTinydns, invalid n')

    const bytes = Buffer.from(TINYDNS.octalToChar(rdata), 'binary')

    return new DNSKEY({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'DNSKEY',
      flags: bytes.readUInt16BE(0),
      protocol: bytes.readUInt8(2),
      algorithm: bytes.readUInt8(3),
      publickey: bytes.slice(4).toString(),
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.UInt16toOctal(this.get('flags')) +
        TINYDNS.UInt8toOctal(this.get('protocol')) +
        TINYDNS.UInt8toOctal(this.get('algorithm')) +
        TINYDNS.escapeOctal(dataRe, this.get('publickey')),
    )
  }
}
