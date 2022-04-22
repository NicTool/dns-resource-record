
import RR from '../rr.js'

export default class KEY extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags (val) {
    // a 2 octet Flags Field
    this.is16bitInt('KEY', 'flags', val)

    this.set('flags', val)
  }

  setProtocol (val) {
    // 1 octet
    this.is8bitInt('KEY', 'protocol', val)

    this.set('protocol', val)
  }

  setAlgorithm (val) {
    // 1 octet
    // 1=RSA/MD5, 2=DH, 3=DSA/SHA-1, 4=EC, 5=RSA/SHA-1
    if (![ 1,2,3,4,5,253,254 ].includes(val))
      throw new Error(`KEY: algorithm invalid, ${this.citeRFC()}`)

    this.set('algorithm', val)
  }

  setPublickey (val) {
    if (!val) throw new Error(`KEY: publickey is required, ${this.citeRFC()}`)

    this.set('publickey', val)
  }

  getDescription () {
    return 'DNS Public Key'
  }

  getRdataFields (arg) {
    return [ 'flags', 'protocol', 'algorithm', 'publickey' ]
  }

  getRFCs () {
    return [ 2535, 3445 ]
  }

  getTypeId () {
    return 25
  }

  /******  IMPORTERS   *******/

  fromBind (opts) {
    // test.example.com  3600  IN  KEY Flags Protocol Algorithm PublicKey
    const [ owner, ttl, c, type, flags, protocol, algorithm ] = opts.bindline.split(/\s+/)
    return new KEY({
      owner,
      ttl      : parseInt(ttl, 10),
      class    : c,
      type     : type,
      flags    : parseInt(flags,     10),
      protocol : parseInt(protocol, 10),
      algorithm: parseInt(algorithm,  10),
      publickey: opts.bindline.split(/\s+/).slice(7).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
}
