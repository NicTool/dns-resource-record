
const net = require('net')

const RR = require('../index.js').RR

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
    const [ owner, ip, ttl, ts, loc ] = str.substring(1).split(':')

    return new this.constructor({
      owner    : this.fullyQualify(owner),
      type     : 'A',
      address  : ip,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  A  192.0.2.127
    const [ owner, ttl, c, type, address ] = str.split(/\s+/)
    return new this.constructor({
      owner,
      ttl  : parseInt(ttl, 10),
      class: c,
      type,
      address,
    })
  }

  /******  EXPORTERS   *******/
  toTinydns () {
    return `+${this.getTinyFQDN('owner')}:${this.get('address')}:${this.getTinydnsPostamble()}\n`
  }
}

module.exports = A