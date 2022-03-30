
const RR = require('./index').RR

class NSEC3 extends RR {
  constructor (opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgoritm (val) {
    // Hash Algorithm is a single octet.
    // The Hash Algorithm field is represented as an unsigned decimal integer.
    if (!val) throw new Error(`NSEC3: 'hash algorithm' is required, ${this.citeRFC()}`)

    this.is8bitInt(val)

    this.set('hash algorithm', val)
  }

  setFlags (val) {
    // The Flags field is represented as an unsigned decimal integer.
    if (!val) throw new Error(`NSEC3: 'flags' is required, ${this.citeRFC()}`)

    this.is8bitInt(val)

    this.set('flags', val)
  }

  setIterations (val) {
    // The Iterations field is represented as an unsigned decimal integer. 0-65535
    if (!val) throw new Error(`NSEC3: 'iterations' is required, ${this.citeRFC()}`)

    this.is16bitInt(val)

    this.set('iterations', val)
  }

  setSalt (val) {
    // The Salt field is represented as a sequence of case-insensitive
    // hexadecimal digits.  Whitespace is not allowed within the
    // sequence.  The Salt field is represented as "-" (without the
    // quotes) when the Salt Length field has a value of 0
    this.set('salt', val)
  }

  setNextHashedOwnerName (val) {
    // The Next Hashed Owner Name field is represented as an unpadded
    // sequence of case-insensitive base32 digits, without whitespace
    if (!val) throw new Error(`NSEC3: 'next hashed owner name' is required, ${this.citeRFC()}`)

    this.set('next hashed owner name', val)
  }

  setTypeBitMaps (val) {
    // The Type Bit Maps field is represented as a sequence of RR type mnemonics.
    if (!val) throw new Error(`NSEC3: 'type bit maps' is required, ${this.citeRFC()}`)

    this.set('type bit maps', val)
  }

  getDescription () {
    return 'Next Secure'
  }

  getRdataFields (arg) {
    return [ 'hash algorithm', 'flags', 'iterations', 'salt', 'next hashed owner name', 'type bit maps' ]
  }

  getRFCs () {
    return [ 5155, 9077 ]
  }

  getTypeId () {
    return 50
  }

  /******  IMPORTERS   *******/
  // fromTinydns (str) {
  // }

  fromBind (str) {
    // test.example.com  3600  IN  NSEC3
    const [ owner, ttl, c, type ] = str.split(/\s+/)
    return new this.constructor({
      owner,
      ttl                     : parseInt(ttl, 10),
      class                   : c,
      type                    : type,
      'hash algorithm'        : '',
      'flags'                 : '',
      'iterations'            : '',
      'salt'                  : '',
      'next hashed owner name': '',
      'type bit maps'         : '',
    })
  }

  /******  EXPORTERS   *******/
  // toBind (zone_opts) {
  //   return `${this.getPrefix(zone_opts)}\t${this.getFQDN('next domain', zone_opts)}\n`
  // }

  // toTinydns () {
  // }
}

// const removeParens = a => ![ '(',')' ].includes(a)

module.exports = NSEC3
