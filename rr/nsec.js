
const RR = require('./index').RR

class NSEC extends RR {
  constructor (opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setNextDomain (val) {
    if (!val) throw new Error(`NSEC: 'next domain' is required: ${this.getRFCs()}`)

    this.isFullyQualified('NSEC', 'next domain', val)
    this.isValidHostname('NSEC', 'next domain', val)

    this.set('next domain', val.toLowerCase())
  }

  setTypeBitMaps (val) {
    if (!val) throw new Error(`NSEC: 'type bit maps' is required: ${this.getRFCs()}`)

    this.set('type bit maps', val)
  }

  getDescription () {
    return 'Next Secure'
  }

  getRdataFields (arg) {
    return [ 'next domain', 'type bit maps' ]
  }

  getRFCs () {
    return [ 4034 ]
  }

  getTypeId () {
    return 47
  }

  /******  IMPORTERS   *******/
  // fromTinydns (str) {
  // }

  fromBind (str) {
    // test.example.com  3600  IN  NSEC NextDomain TypeBitMaps
    const [ fqdn, ttl, c, type, next ] = str.split(/\s+/)
    return new this.constructor({
      class          : c,
      type           : type,
      name           : fqdn,
      ttl            : parseInt(ttl, 10),
      'next domain'  : next,
      'type bit maps': str.split(/\s+/).slice(5).filter(removeParens).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
  // toBind (zone_opts) {
  //   return `${this.getPrefix(zone_opts)}\t${this.getFQDN('next domain', zone_opts)}\n`
  // }

  // toTinydns () {
  // }
}

const removeParens = a => ![ '(',')' ].includes(a)

module.exports = NSEC
