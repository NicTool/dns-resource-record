
import RR from '../rr.js'

export default class IPSECKEY extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPrecedence (val) {
    // an 8-bit precedence for this record.
    this.is8bitInt('IPSECKEY', 'precedence', val)

    this.set('precedence', val)
  }

  setGatewayType (val) {
    // 0 (none), 1 (4-byte IPv4), 2 (16-byte IPv6), 3 (wire encoded domain name)
    if (![ 0,1,2,3 ].includes(val))
      throw new Error(`IPSECKEY: Gateway Type is invalid, ${this.citeRFC()}`)

    this.set('gateway type', val)
  }

  setAlgorithm (val) {
    // unsigned int, 1 octet, values: 1=DSA, 2=RSA
    if (![ 1,2 ].includes(val))
      throw new Error(`IPSECKEY: Algorithm invalid, ${this.citeRFC()}`)

    this.set('algorithm', val)
  }

  setGateway (val) {
    if (this.get('gateway') === 0 && val !== '.')
      throw new Error(`IPSECKEY: gateway invalid, ${this.citeRFC()}`)

    this.set('gateway', val)
  }

  setPublickey (val) {
    if (!val) throw new Error(`IPSECKEY: publickey is required, ${this.citeRFC()}`)

    this.set('publickey', val)
  }

  getDescription () {
    return 'IPsec Keying'
  }

  getRdataFields (arg) {
    return [ 'precedence', 'gateway type', 'algorithm', 'gateway', 'publickey' ]
  }

  getRFCs () {
    return [ 4025 ]
  }

  getTypeId () {
    return 45
  }

  /******  IMPORTERS   *******/

  fromBind (str) {
    // FQDN TTL CLASS IPSECKEY Precedence GatewayType Algorithm Gateway PublicKey
    const [ owner, ttl, c, type, prec, gwt, algo, gateway, publickey ] = str.split(/\s+/)
    return new IPSECKEY({
      owner,
      ttl           : parseInt(ttl, 10),
      class         : c,
      type,
      precedence    : parseInt(prec, 10),
      'gateway type': parseInt(gwt,  10),
      algorithm     : parseInt(algo, 10),
      gateway,
      publickey,
    })
  }

  /******  EXPORTERS   *******/
}
