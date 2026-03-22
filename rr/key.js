import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

export default class KEY extends RR {
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

    this.set('publickey', val)
  }

  getDescription() {
    return 'DNS Public Key'
  }

  getRdataFields(arg) {
    return ['flags', 'protocol', 'algorithm', 'publickey']
  }

  getRFCs() {
    return [2535, 3445]
  }

  getTypeId() {
    return 25
  }

  /******  IMPORTERS   *******/

  fromBind(opts) {
    // test.example.com  3600  IN  KEY Flags Protocol Algorithm PublicKey
    const [owner, ttl, c, type, flags, protocol, algorithm] = opts.bindline.split(/\s+/)
    return new KEY({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      flags: parseInt(flags, 10),
      protocol: parseInt(protocol, 10),
      algorithm: parseInt(algorithm, 10),
      publickey: opts.bindline.split(/\s+/).slice(7).join(' ').trim(),
    })
  }

  fromTinydns({ rd, owner, ttl }) {
    // RDATA format: Flags (6 octal chars) + Protocol (3 octal chars) + Algorithm (3 octal chars) + Public Key (escaped data)
    if (rd.length < 12) {
      this.throwHelp(`KEY: RDATA too short: ${rd}`)
    }

    return new KEY({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'KEY',
      flags: TINYDNS.octalToUInt16(rd.slice(0, 6)),
      protocol: TINYDNS.octalToUInt8(rd.slice(6, 9)),
      algorithm: TINYDNS.octalToUInt8(rd.slice(9, 12)),
      publickey: TINYDNS.unescapeOctal(rd.slice(12)),
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
