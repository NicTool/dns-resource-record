
const net = require('net')

const RR = require('./index').RR

class MX extends RR {
  constructor (opts) {
    super(opts)

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)

    this.set('id', 15)
    this.setExchange(opts?.exchange)
    this.setWeight(opts?.weight)
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

  getRFCs () {
    return [ 1035, 7505 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // MX =>  @ fqdn:ip:x:dist:ttl:timestamp:lo
    // eslint-disable-next-line no-unused-vars
    const [ name, ip, x, weight, ttl, ts, loc ] = str.substring(1).split(':')

    return new this.constructor({
      type     : 'MX',
      name     : name,
      // address  : ip,
      exchange : x,
      weight   : parseInt(weight, 10) || 0,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind () {
    //
  }

  /******  EXPORTERS   *******/
  toBind () {
    const fields = [ 'name', 'ttl', 'class', 'type', 'weight', 'exchange' ]
    return `${fields.map(f => this.get(f)).join('\t')}\n`
  }

  toTinydns () {
    return `@${this.get('name')}::${this.get('exchange')}:${this.get('weight')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = MX
