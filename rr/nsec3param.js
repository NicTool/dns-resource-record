import RR from '../rr.js'

export default class NSEC3PARAM extends RR {
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgorithm(val) {
    // Hash Algorithm is a single octet.
    // The Hash Algorithm field is represented as an unsigned decimal integer.
    if (!val) this.throwHelp(`NSEC3PARAM: 'hash algorithm' is required`)

    this.is8bitInt('NSEC3PARAM', 'hash algorithm', val)

    this.set('hash algorithm', val)
  }

  setFlags(val) {
    // The Flags field is represented as an unsigned decimal integer.
    if (!val) this.throwHelp(`NSEC3PARAM: 'flags' is required`)

    this.is8bitInt('NSEC3PARAM', 'flags', val)

    this.set('flags', val)
  }

  setIterations(val) {
    // The Iterations field is represented as an unsigned decimal integer. 0-65535
    if (!val) this.throwHelp(`NSEC3PARAM: 'iterations' is required`)

    this.is16bitInt('NSEC3PARAM', 'iterations', val)

    this.set('iterations', val)
  }

  setSalt(val) {
    // The Salt field is represented as a sequence of case-insensitive
    // hexadecimal digits.  Whitespace is not allowed within the
    // sequence.  The Salt field is represented as "-" (without the
    // quotes) when the Salt Length field has a value of 0
    this.set('salt', val)
  }

  getDescription() {
    return 'Next Secure Parameters'
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

  fromBind(str) {
    // test.example.com  3600  IN  NSEC3PARAM
    const [owner, ttl, c, type] = str.split(/\s+/)
    return new NSEC3PARAM({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'hash algorithm': '',
      flags: '',
      iterations: '',
      salt: '',
      'next hashed owner name': '',
      'type bit maps': '',
    })
  }

  /******  EXPORTERS   *******/
}
