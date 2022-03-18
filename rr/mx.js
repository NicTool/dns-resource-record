
const net = require('net')

const RR = require('./index').RR

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
      throw new Error(`MX: exchange must be a FQDN: ${this.getRFCs()}`)

    this.fullyQualified('MX', 'exchange', val)
    this.validHostname('MX', 'exchange', val)

    this.set('exchange', val)
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
    const [ fqdn, ip, x, preference, ttl, ts, loc ] = str.substring(1).split(':')

    return new this.constructor({
      type      : 'MX',
      name      : fqdn,
      exchange  : x,
      preference: parseInt(preference, 10) || 0,
      ttl       : parseInt(ttl, 10),
      timestamp : ts,
      location  : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  MX  preference exchange
    const [ fqdn, ttl, c, type, preference, exchange ] = str.split(/\s+/)

    return new this.constructor({
      class     : c,
      type      : type,
      name      : fqdn,
      preference: parseInt(preference),
      exchange  : exchange,
      ttl       : parseInt(ttl, 10),
    })
  }

  /******  EXPORTERS   *******/
  toTinydns () {
    return `@${this.get('name')}::${this.get('exchange')}:${this.get('preference')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = MX
