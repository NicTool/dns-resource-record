import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class NSEC3 extends RR {
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgorithm(val) {
    // Hash Algorithm is a single octet.
    // The Hash Algorithm field is represented as an unsigned decimal integer.
    if (!val)
      throw new Error(`NSEC3: 'hash algorithm' is required, ${this.citeRFC()}`)

    this.is8bitInt('NSEC3', 'hash algorithm', val)

    this.set('hash algorithm', val)
  }

  setFlags(val) {
    // The Flags field is represented as an unsigned decimal integer.
    if (!val) throw new Error(`NSEC3: 'flags' is required, ${this.citeRFC()}`)

    this.is8bitInt('NSEC3', 'flags', val)

    this.set('flags', val)
  }

  setIterations(val) {
    // The Iterations field is represented as an unsigned decimal integer. 0-65535
    if (!val)
      throw new Error(`NSEC3: 'iterations' is required, ${this.citeRFC()}`)

    this.is16bitInt('NSEC3', 'flags', val)

    this.set('iterations', val)
  }

  setSalt(val) {
    // The Salt field is represented as a sequence of case-insensitive
    // hexadecimal digits.  Whitespace is not allowed within the
    // sequence.  The Salt field is represented as "-" (without the
    // quotes) when the Salt Length field has a value of 0
    this.set('salt', val)
  }

  setNextHashedOwnerName(val) {
    // The Next Hashed Owner Name field is represented as an unpadded
    // sequence of case-insensitive base32 digits, without whitespace
    if (!val)
      throw new Error(
        `NSEC3: 'next hashed owner name' is required, ${this.citeRFC()}`,
      )

    this.set('next hashed owner name', val)
  }

  setTypeBitMaps(val) {
    // The Type Bit Maps field is represented as a sequence of RR type mnemonics.
    if (!val)
      throw new Error(`NSEC3: 'type bit maps' is required, ${this.citeRFC()}`)

    this.set('type bit maps', val)
  }

  getDescription() {
    return 'Next Secure'
  }

  getRdataFields(arg) {
    return [
      'hash algorithm',
      'flags',
      'iterations',
      'salt',
      'next hashed owner name',
      'type bit maps',
    ]
  }

  getRFCs() {
    return [5155, 9077]
  }

  getTypeId() {
    return 50
  }

  /******  IMPORTERS   *******/

  fromBind(opts) {
    // test.example.com. 3600 IN NSEC3 1 1 12 aabbccdd (2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG)
    const [owner, ttl, c, type, ha, flags, iterations, salt] =
      opts.bindline.split(/\s+/)
    const rdata = opts.bindline.split(/\(|\)/)[1]

    return new NSEC3({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'hash algorithm': parseInt(ha, 10),
      flags: parseInt(flags, 10),
      iterations: parseInt(iterations, 10),
      salt,
      'next hashed owner name': rdata.split(/\s+/)[0],
      'type bit maps': rdata.split(/\s+/).slice(1).join('\t'),
    })
  }

  fromTinydns(opts) {
    const [fqdn, n, rdata, ttl, ts, loc] = opts.tinyline.substring(1).split(':')
    if (n != 50) throw new Error('NSEC3 fromTinydns, invalid n')

    const bytes = Buffer.from(TINYDNS.octalToChar(rdata), 'binary')

    return new NSEC3({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'NSEC3',
      'hash algorithm': bytes.readUInt8(0),
      flags: bytes.readUInt8(1),
      iterations: bytes.readUInt16BE(2),
      // salt                    : ,
      // 'next hashed owner name': ,
      // 'type bit maps'         : ,
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  /******  EXPORTERS   *******/

  toBind(zone_opts) {
    return `${this.getFQDN('owner', zone_opts)}\t${this.get('ttl')}\t${this.get('class')}\tNSEC3${this.getRdataFields()
      .slice(0, 4)
      .map((f) => '\t' + this.get(f))
      .join('')}\t(${this.getRdataFields()
      .slice(4)
      .map((f) => this.get(f))
      .join('\t')})\n`
  }

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.UInt8toOctal(this.get('hash algorithm')) +
        TINYDNS.UInt8toOctal(this.get('flags')) +
        TINYDNS.UInt16toOctal(this.get('iterations')) +
        TINYDNS.escapeOctal(dataRe, this.get('salt')) +
        TINYDNS.escapeOctal(dataRe, this.get('next hashed owner name')) +
        TINYDNS.escapeOctal(dataRe, this.get('type bit maps')),
    )
  }
}
