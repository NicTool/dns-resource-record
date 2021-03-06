
import net from 'net'

import RR from '../rr.js'

export default class A extends RR {
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
  fromTinydns (opts) {
    // +fqdn:ip:ttl:timestamp:lo
    const [ owner, ip, ttl, ts, loc ] = opts.tinyline.substring(1).split(':')

    return new A({
      owner    : this.fullyQualify(owner),
      type     : 'A',
      address  : ip,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (opts) {
    // test.example.com  3600  IN  A  192.0.2.127
    const [ owner, ttl, c, type, address ] = opts.bindline.split(/\s+/)
    return new A({
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
