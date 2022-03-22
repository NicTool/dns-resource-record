
const net = require('net')

const RR = require('./index').RR

class A extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress (val) {
    if (!val) throw new Error('A: address is required')
    if (!net.isIPv4(val)) throw new Error('A address must be IPv4')
    this.set('address', val)
  }

  getDescription () {
    return 'Address'
  }

  getRdataFields (arg) {
    return [ 'address' ]
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
      name     : this.fullyQualify(fqdn),
      type     : 'A',
      address  : ip,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  A  192.0.2.127
    const [ name, ttl, c, type, addr ] = str.split(/\s+/)
    return new this.constructor({
      name   : name,
      class  : c,
      type   : type,
      address: addr,
      ttl    : parseInt(ttl, 10),
    })
  }

  /******  EXPORTERS   *******/
  toTinydns () {
    return `+${this.getTinyFQDN('name')}:${this.get('address')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = A