
const RR = require('./index').RR

class NSEC3PARAM extends RR {
  constructor (opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgoritm (val) {
    // Hash Algorithm is a single octet.
    // The Hash Algorithm field is represented as an unsigned decimal integer.
    if (!val) throw new Error(`NSEC3PARAM: 'hash algorithm' is required: ${this.getRFCs()}`)

    this.is8bitInt(val)

    this.set('hash algorithm', val)
  }

  setFlags (val) {
    // The Flags field is represented as an unsigned decimal integer.
    if (!val) throw new Error(`NSEC3PARAM: 'flags' is required: ${this.getRFCs()}`)

    this.is8bitInt(val)

    this.set('flags', val)
  }

  setIterations (val) {
    // The Iterations field is represented as an unsigned decimal integer. 0-65535
    if (!val) throw new Error(`NSEC3PARAM: 'iterations' is required: ${this.getRFCs()}`)

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

  getDescription () {
    return 'Next Secure Parameters'
  }

  getRdataFields (arg) {
    return [ 'hash algorithm', 'flags', 'iterations', 'salt' ]
  }

  getRFCs () {
    return [ 5155 ]
  }

  getTypeId () {
    return 51
  }

  /******  IMPORTERS   *******/

  fromBind (str) {
    // test.example.com  3600  IN  NSEC3PARAM
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

}

// const removeParens = a => ![ '(',')' ].includes(a)

module.exports = NSEC3PARAM
