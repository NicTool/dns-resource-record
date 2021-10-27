
const net = require('net')

const RR = require('./index').RR

class A extends RR {
  constructor (opts) {
    super(opts)

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

    this.set('id', 1)
    this.setAddress(opts.address)
  }

  /****** Resource record specific setters   *******/
  setAddress (val) {
    if (!val) throw new Error('A: address is required')
    if (!net.isIPv4(val)) throw new Error('A address must be IPv4')
    this.set('address', val)
  }

  getFields () {
    return [ 'name', 'ttl', 'class', 'type', 'address' ]
  }

  getRFCs () {
    return [ 1035 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // +fqdn:ip:ttl:timestamp:lo
    const [ fqdn, ip, ttl, ts, loc ] = str.substring(1).split(':')

    return new this.constructor({
      type     : 'A',
      name     : fqdn,
      address  : ip,
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
    return `${this.getFields().map(f => this.get(f)).join('\t')}\n`
  }

  toTinydns () {
    return `+${this.get('name')}:${this.get('address')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = A