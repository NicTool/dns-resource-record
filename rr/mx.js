
const net = require('net')

const RR = require('../index.js').RR

class MX extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPreference (val) {
    if (val === undefined) val = this?.default?.preference
    this.is16bitInt('MX', 'preference', val)
    this.set('preference', val)
  }

  setExchange (val) {
    if (!val) throw new Error('MX: exchange is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`MX: exchange must be a FQDN, ${this.citeRFC()}`)

    this.isFullyQualified('MX', 'exchange', val)
    this.isValidHostname('MX', 'exchange', val)

    // RFC 4034: letters in the DNS names ... are lower cased
    this.set('exchange', val.toLowerCase())
  }

  getDescription () {
    return 'Mail Exchanger'
  }

  getRdataFields (arg) {
    return [ 'preference', 'exchange' ]
  }

  getRFCs () {
    return [ 1035, 2181, 7505 ]
  }

  getTypeId () {
    return 15
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // @fqdn:ip:x:dist:ttl:timestamp:lo
    // eslint-disable-next-line no-unused-vars
    const [ owner, ip, x, preference, ttl, ts, loc ] = str.substring(1).split(':')

    return new this.constructor({
      type      : 'MX',
      owner     : this.fullyQualify(owner),
      exchange  : this.fullyQualify(/\./.test(x) ? x : `${x}.mx.${owner}`),
      preference: parseInt(preference, 10) || 0,
      ttl       : parseInt(ttl, 10),
      timestamp : ts,
      location  : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  MX  preference exchange
    const [ owner, ttl, c, type, preference, exchange ] = str.split(/\s+/)

    return new this.constructor({
      owner,
      ttl       : parseInt(ttl, 10),
      class     : c,
      type,
      preference: parseInt(preference),
      exchange,
    })
  }

  /******  EXPORTERS   *******/
  toBind (zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.get('preference')}\t${this.getFQDN('exchange', zone_opts)}\n`
  }

  toTinydns () {
    return `@${this.getTinyFQDN('owner')}::${this.getTinyFQDN('exchange')}:${this.get('preference')}:${this.getTinydnsPostamble()}\n`
  }
}

module.exports = MX
