
const RR = require('./index').RR

class SIG extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTypeCovered (val) {
    // a 2 octet Type Covered field
    if (!val) throw new Error(`SIG: 'type covered' is required`)

    this.set('type covered', val)
  }

  setAlgorithm (val) {
    // a 1 octet Algorithm field

    this.is8bitInt('SIG', 'labels', val)

    this.set('algorithm', val)
  }

  setLabels (val) {
    // a 1 octet Labels field
    this.is8bitInt('SIG', 'labels', val)

    this.set('labels', val)
  }

  setOriginalTtl (val) {
    // a 4 octet Original TTL field
    this.is32bitInt('SIG', 'original ttl', val)

    this.set('original ttl', val)
  }

  setSignatureExpiration (val) {
    // a 4 octet Signature Expiration field
    this.set('signature expiration', val)
  }

  setSignatureInception (val) {
    // a 4 octet Signature Inception field
    this.set('signature inception', val)
  }

  setKeyTag (val) {
    // a 2 octet Key tag
    this.set('key tag', val)
  }

  setSignersName (val) {
    // the domain name of the signer generating the SIG RR

    // RFC 4034: letters in the DNS names are lower cased
    this.set('signers name', val.toLowerCase())
  }

  setSignature (val) {
    // the Signature field.

    this.set('signature', val)
  }

  getDescription () {
    return 'Signature'
  }

  getRdataFields (arg) {
    return [
      'type covered', 'algorithm', 'labels', 'original ttl', 'signature expiration',
      'signature inception', 'key tag', 'signers name', 'signature',
    ]
  }

  getRFCs () {
    return [ 2535 ]
  }

  getTypeId () {
    return 24
  }

  /******  IMPORTERS   *******/
  // fromBind (str) {
  //   // test.example.com  3600  IN  SIG ...
  //   const [ owner, ttl, c, type ] = str.split(/\s+/)
  //   return new this.constructor({
  //     owner,
  //     ttl          : parseInt(ttl, 10),
  //     class        : c,
  //     type         : type,
  //   })
  // }

  /******  EXPORTERS   *******/

}

module.exports = SIG
