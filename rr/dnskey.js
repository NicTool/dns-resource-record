
const RR = require('./index').RR

class DS extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags (val) {
    // a 2 octet Flags Field
    // the possible values are: 0, 256, and 257 RFC 4034
    if (![ 0, 256, 257 ].includes(val)) throw new Error(`DS: flags invalid, see ${this.getRFCs()}`)

    this.set('flags', val)
  }

  setProtocol (val) {
    // The Protocol Field MUST be represented as an unsigned decimal integer with a value of 3.
    if (![ 3 ].includes(val)) throw new Error(`DS: protocol invalid, see ${this.getRFCs()}`)

    this.set('protocol', val)
  }

  setAlgorithm (val) {
    // 1=RSA/MD5, 2=DH, 3=DSA/SHA-1, 4=EC, 5=RSA/SHA-1
    if (![ 1,2,3,4,5,253,254 ].includes(val))
      throw new Error(`DS: algorithm invalid, see ${this.getRFCs()}`)

    this.set('algorithm', val)
  }

  setPublickey (val) {
    if (!val) throw new Error(`DS: publickey is required, see ${this.getRFCs()}`)

    this.set('publickey', val)
  }

  getDescription () {
    return 'DNS Public Key'
  }

  getRdataFields (arg) {
    return [ 'flags', 'protocol', 'algorithm', 'publickey' ]
  }

  getRFCs () {
    return [ 4034 ]
  }

  getTypeId () {
    return 48
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
  }

  fromBind (str) {
    // test.example.com  3600  IN  DNSKEY Flags Protocol Algorithm PublicKey
    const [ fqdn, ttl, c, type, flags, protocol, algorithm ] = str.split(/\s+/)
    return new this.constructor({
      name     : fqdn,
      ttl      : parseInt(ttl, 10),
      class    : c,
      type     : type,
      flags    : parseInt(flags,     10),
      protocol : parseInt(protocol, 10),
      algorithm: parseInt(algorithm,  10),
      publickey: str.split(/\s+/).slice(7).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
  // toTinydns () {
  //   const rdata = '' // TODO
  //   return this.getTinydnsGeneric(rdata)
  // }
}

module.exports = DS
