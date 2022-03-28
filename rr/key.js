
const RR = require('./index').RR

class KEY extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags (val) {
    // a 2 octet Flags Field
    this.is16bitInt(val)

    this.set('flags', val)
  }

  setProtocol (val) {
    // 1 octet
    this.is8bitInt(val)

    this.set('protocol', val)
  }

  setAlgorithm (val) {
    // 1 octet
    // 1=RSA/MD5, 2=DH, 3=DSA/SHA-1, 4=EC, 5=RSA/SHA-1
    if (![ 1,2,3,4,5,253,254 ].includes(val))
      throw new Error(`KEY: algorithm invalid, see ${this.getRFCs()}`)

    this.set('algorithm', val)
  }

  setPublickey (val) {
    if (!val) throw new Error(`KEY: publickey is required, see ${this.getRFCs()}`)

    this.set('publickey', val)
  }

  getDescription () {
    return 'DNS Public Key'
  }

  getRdataFields (arg) {
    return [ 'flags', 'protocol', 'algorithm', 'publickey' ]
  }

  getRFCs () {
    return [ 2535 ]
  }

  getTypeId () {
    return 25
  }

  /******  IMPORTERS   *******/
  // fromTinydns (str) {
  // }

  fromBind (str) {
    // test.example.com  3600  IN  KEY Flags Protocol Algorithm PublicKey
    const [ owner, ttl, c, type, flags, protocol, algorithm ] = str.split(/\s+/)
    return new this.constructor({
      owner,
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

module.exports = KEY