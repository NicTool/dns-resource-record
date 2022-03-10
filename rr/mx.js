
const net = require('net')

const RR = require('./index').RR

class MX extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setExchange (val) {
    if (!val) throw new Error('MX: exchange is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`MX: exchange must be a FQDN: RFC 2181`)

    if (!this.fullyQualified('MX', 'exchange', val)) return
    if (!this.validHostname('MX', 'exchange', val)) return
    this.set('exchange', val)
  }

  setWeight (val) {
    if (!this.is16bitInt('MX', 'weight', val)) return
    this.set('weight', val)
  }

  getDescription () {
    return 'Mail Exchanger'
  }

  getRdataFields (arg) {
    return [ 'weight', 'exchange' ]
  }

  getRFCs () {
    return [ 1035, 7505 ]
  }

  getTypeId () {
    return 15
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // @fqdn:ip:x:dist:ttl:timestamp:lo
    // eslint-disable-next-line no-unused-vars
    const [ fqdn, ip, x, weight, ttl, ts, loc ] = str.substring(1).split(':')

    return new this.constructor({
      type     : 'MX',
      name     : fqdn,
      exchange : x,
      weight   : parseInt(weight, 10) || 0,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  MX  weight exchange
    const [ fqdn, ttl, c, type, weight, exchange ] = str.split(/\s+/)

    return new this.constructor({
      class   : c,
      type    : type,
      name    : fqdn,
      weight  : parseInt(weight),
      exchange: exchange,
      ttl     : parseInt(ttl, 10),
    })
  }

  /******  EXPORTERS   *******/
  toTinydns () {
    return `@${this.get('name')}::${this.get('exchange')}:${this.get('weight')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = MX
