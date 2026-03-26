import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

export default class NSEC3PARAM extends RR {
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgorithm(val) {
    // Hash Algorithm is a single octet.
    // The Hash Algorithm field is represented as an unsigned decimal integer.
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'hash algorithm' is required`)

    this.is8bitInt('NSEC3PARAM', 'hash algorithm', val)

    this.set('hash algorithm', val)
  }

  setFlags(val) {
    // The Flags field is represented as an unsigned decimal integer.
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'flags' is required`)

    this.is8bitInt('NSEC3PARAM', 'flags', val)

    this.set('flags', val)
  }

  setIterations(val) {
    // The Iterations field is represented as an unsigned decimal integer. 0-65535
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'iterations' is required`)

    this.is16bitInt('NSEC3PARAM', 'iterations', val)

    this.set('iterations', val)
  }

  setSalt(val) {
    // The Salt field is represented as a sequence of case-insensitive
    // hexadecimal digits.  Whitespace is not allowed within the
    // sequence.  The Salt field is represented as "-" (without the
    // quotes) when the Salt Length field has a value of 0
    if (val === '-') {
      this.set('salt', val)
      return
    }

    if (val !== undefined && val !== null && !/^[0-9A-Fa-f]*$/.test(val)) {
      this.throwHelp(`NSEC3PARAM: 'salt' must be hex or '-'`)
    }

    this.set('salt', val)
  }

  getDescription() {
    return 'Next Secure Parameters'
  }

  getTags() {
    return ['dnssec']
  }

  getRdataFields(arg) {
    return ['hash algorithm', 'flags', 'iterations', 'salt']
  }

  getRFCs() {
    return [5155]
  }

  getTypeId() {
    return 51
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  NSEC3PARAM  <hash> <flags> <iterations> <salt>
    // Example: test.example.com. 3600 IN NSEC3PARAM 1 1 12 aabbccdd
    const [owner, ttl, c, type, ha, flags, iterations, salt] = bindline.split(/\s+/)
    return new NSEC3PARAM({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'hash algorithm': parseInt(ha, 10),
      flags: parseInt(flags, 10),
      iterations: parseInt(iterations, 10),
      salt: salt,
    })
  }

  fromTinydns({ tinyline }) {
    // RDATA format: Hash Algorithm (3 octal chars) + Flags (3 octal chars) + Iterations (6 octal chars) + Salt (escaped hex string)
    const [owner, _typeId, rd, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (rd.length < 4) {
      this.throwHelp(`NSEC3PARAM: RDATA too short: ${rd}`)
    }

    // rd may contain actual binary characters (from JS string '\\001' -> char 0x01),
    // so convert via octalToChar and read bytes from a Buffer for robust parsing.
    const bytes = Buffer.from(TINYDNS.octalToChar(rd), 'binary')

    return new NSEC3PARAM({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'NSEC3PARAM',
      'hash algorithm': bytes.readUInt8(0),
      flags: bytes.readUInt8(1),
      iterations: bytes.readUInt16BE(2),
      salt: bytes.slice(4).toString('utf8'),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toBind(zone_opts) {
    // Example: test.example.com. 3600 IN NSEC3PARAM 1 1 12 aabbccdd
    return `${this.getFQDN('owner', zone_opts)}	${this.get('ttl')}	${this.get('class')}	NSEC3PARAM	${this.get('hash algorithm')}	${this.get('flags')}	${this.get('iterations')}	${this.get('salt')}
`
  }

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.UInt8toOctal(this.get('hash algorithm')) +
        TINYDNS.UInt8toOctal(this.get('flags')) +
        TINYDNS.UInt16toOctal(this.get('iterations')) +
        TINYDNS.escapeOctal(dataRe, this.get('salt')),
    )
  }
}
