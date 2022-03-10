
const net = require('net')

const RR = require('./index').RR

class A extends RR {
  constructor (opts) {
    super(opts)
    if (opts === null) return

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

    this.setAddress(opts.address)
  }

  /****** Resource record specific setters   *******/
  setAddress (val) {
    if (!val) throw new Error('A: address is required')
    if (!net.isIPv4(val)) throw new Error('A address must be IPv4')
    this.set('address', val)
  }

  getFields (arg) {
    switch (arg) {
      case 'common':
        return this.getCommonFields()
      case 'rdata':
        return [ 'address' ]
      default:
        return this.getCommonFields().concat([ 'address' ])
    }
  }

  getRFCs () {
    return [ 1035 ]
  }

  getTypeId () {
    return 1
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

  fromBind (str) {
    // test.example.com  3600  IN  A  192.0.2.127
    const [ fqdn, ttl, c, type, ip ] = str.split(/\s+/)
    return new this.constructor({
      class  : c,
      type   : type,
      name   : fqdn,
      address: ip,
      ttl    : parseInt(ttl, 10),
    })
  }

  /******  EXPORTERS   *******/
  toTinydns () {
    return `+${this.get('name')}:${this.get('address')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = A