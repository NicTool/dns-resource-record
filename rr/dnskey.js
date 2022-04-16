
const RR = require('../index.js').RR

class DNSKEY extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags (val) {
    // a 2 octet Flags Field
    // the possible values are: 0, 256, and 257 RFC 4034
    if (![ 0, 256, 257 ].includes(val)) throw new Error(`DNSKEY: flags invalid, ${this.citeRFC()}`)

    this.set('flags', val)
  }

  setProtocol (val) {
    // 1 octet
    // The Protocol Field MUST be represented as an unsigned decimal integer with a value of 3.
    if (![ 3 ].includes(val)) throw new Error(`DNSKEY: protocol invalid, ${this.citeRFC()}`)

    this.set('protocol', val)
  }

  setAlgorithm (val) {
    // 1 octet
    // 1=RSA/MD5, 2=DH, 3=DSA/SHA-1, 4=EC, 5=RSA/SHA-1
    if (![ 1,2,3,4,5,253,254 ].includes(val))
      throw new Error(`DNSKEY: algorithm invalid, ${this.citeRFC()}`)

    this.set('algorithm', val)
  }

  setPublickey (val) {
    if (!val) throw new Error(`DNSKEY: publickey is required, ${this.citeRFC()}`)

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
  // fromTinydns (str) {
  // }

  fromBind (str) {
    // test.example.com  3600  IN  DNSKEY Flags Protocol Algorithm PublicKey
    const match = str.match(/^([^\s]+)\s+([0-9]+)\s+(\w+)\s+(\w+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+\s*(.*?)\s*$/)
    if (!match) throw new Error(`unable to parse DNSKEY: ${str}`)
    const [ owner, ttl, c, type, flags, protocol, algorithm, publickey ] = match.slice(1)

    return new this.constructor({
      owner,
      ttl      : parseInt(ttl, 10),
      class    : c,
      type     : type,
      flags    : parseInt(flags,     10),
      protocol : parseInt(protocol, 10),
      algorithm: parseInt(algorithm,  10),
      publickey: publickey,
    })
  }

  /******  EXPORTERS   *******/
  // toTinydns () {
  //   const rdata = '' // TODO
  //   return this.getTinydnsGeneric(rdata)
  // }
}

module.exports = DNSKEY
