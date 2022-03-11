
const RR = require('./index').RR

class DS extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setKeytag (val) {
    // a 2 octet Key Tag field...in network byte order
    if (!val) throw new Error(`DS: keytagtag is required`)
    if (val.length > 2) throw new Error(`DS: keytag is too long, see ${this.getRFCs()}`)

    this.set('keytag', val)
  }

  setAlgorithm (val) {
    // 1=RSA/MD5, 2=DH, 3=DSA/SHA-1, 4=EC, 5=RSA/SHA-1
    if (![ 1,2,3,4,5,253,254 ].includes(val))
      throw new Error(`DS: algorithm invalid, see ${this.getRFCs()}`)

    this.set('algorithm', val)
  }

  setDigesttype (val) {
    if (![ 1,2 ].includes(val)) throw new Error(`DS: digesttype invalid, see ${this.getRFCs()}`)

    this.set('digesttype', val)
  }

  setDigest (val) {
    if (!val) throw new Error(`DS: digest is required, see ${this.getRFCs()}`)

    this.set('digest', val)
  }

  getDescription () {
    return 'Delegation Signer'
  }

  getRdataFields (arg) {
    return [ 'keytag', 'algorithm', 'digesttype', 'digest' ]
  }

  getRFCs () {
    return [ 4034, 4509 ]
  }

  getTypeId () {
    return 43
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
  }

  fromBind (str) {
    // test.example.com  3600  IN  DS Key Tag Algorithm, Digest Type, Digest
    const [ fqdn, ttl, c, type, keytag, algorithm, digesttype ] = str.split(/\s+/)
    return new this.constructor({
      name      : fqdn,
      ttl       : parseInt(ttl, 10),
      class     : c,
      type      : type,
      keytag    : parseInt(keytag,     10),
      algorithm : parseInt(algorithm,  10),
      digesttype: parseInt(digesttype, 10),
      digest    : str.split(/\s+/).slice(7).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
  toTinydns () {
  }
}

module.exports = DS
