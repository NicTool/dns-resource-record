import RR from '../rr.js'

export default class RRSIG extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTypeCovered(val) {
    // a 2 octet Type Covered field
    if (!val) this.throwHelp(`RRSIG: 'type covered' is required`)
    if (val.length > 2) this.throwHelp(`RRSIG: 'type covered' is too long`)

    this.set('type covered', val)
  }

  setAlgorithm(val) {
    // a 1 octet Algorithm field
    if (!this.getAlgorithmOptions().has(val))
      this.throwHelp(`RRSIG: algorithm invalid`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'RRSIGA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [253],
      [254],
    ])
  }

  setLabels(val) {
    // a 1 octet Labels field
    this.is8bitInt('RRSIG', 'labels', val)

    this.set('labels', val)
  }

  setOriginalTtl(val) {
    // a 4 octet Original TTL field
    this.is32bitInt('RRSIG', 'original ttl', val)

    this.set('original ttl', val)
  }

  setSignatureExpiration(val) {
    // a 4 octet Signature Expiration field
    this.set('signature expiration', val)
  }

  setSignatureInception(val) {
    // a 4 octet Signature Inception field
    this.set('signature inception', val)
  }

  setKeyTag(val) {
    // a 2 octet Key tag
    this.set('key tag', val)
  }

  setSignersName(val) {
    // the Signer's Name field
    this.set('signers name', val)
  }

  setSignature(val) {
    // the Signature field.

    this.set('signature', val)
  }

  getDescription() {
    return 'Resource Record Signature'
  }

  getRdataFields(arg) {
    return [
      'type covered',
      'algorithm',
      'labels',
      'original ttl',
      'signature expiration',
      'signature inception',
      'key tag',
      'signers name',
      'signature',
    ]
  }

  getRFCs() {
    return [4034]
  }

  getTypeId() {
    return 46
  }

  /******  IMPORTERS   *******/

  // fromBind (str) {
  //   // test.example.com  3600  IN  RRSIG ...
  //   const [ owner, ttl, c, type ] = str.split(/\s+/)
  //   return new RRSIG({
  //     owner,
  //     ttl          : parseInt(ttl, 10),
  //     class        : c,
  //     type         : type,
  //   })
  // }

  /******  EXPORTERS   *******/
}
