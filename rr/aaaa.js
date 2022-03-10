
const net = require('net')

const RR      = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class AAAA extends RR {
  constructor (opts) {
    super(opts)
    if (opts === null) return

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

    this.setAddress(opts?.address)
  }

  /****** Resource record specific setters   *******/
  setAddress (val) {
    if (!val) throw new Error('AAAA: address is required')
    if (!net.isIPv6(val)) throw new Error('AAAA: address must be IPv6')

    this.set('address', val.toLowerCase()) // IETFs suggest only lower case
  }

  getCompressed (f) {
    this.compress(this.get(f))
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
    return [ 3596 ]
  }

  getTypeId () {
    return 28
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    let fqdn, ip, n, rdata, ttl, ts, loc

    switch (str[0]) {
      case ':':
        // GENERIC  =>  :fqdn:28:rdata:ttl:timestamp:lo
        [ fqdn, n, rdata, ttl, ts, loc ] = str.substring(1).split(':')
        if (n != 28) throw new Error('SRV fromTinydns, invalid n')
        // compressed format is needed for test comparisons
        ip = this.compress(TINYDNS.octalToHex(rdata).match(/([0-9a-fA-F]{4})/g).join(':'))
        break
      case '3':
      case '6':
        // AAAA     =>  3 fqdn:rdata:x:ttl:timestamp:lo
        // AAAA,PTR =>  6 fqdn:rdata:x:ttl:timestamp:lo
        [ fqdn, rdata, ttl, ts, loc ] = str.substring(1).split(':')
        ip = rdata.match(/(.{4})/g).join(':')
        break
    }

    return new this.constructor({
      type     : 'AAAA',
      name     : fqdn,
      address  : ip,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  AAAA  ...
    const [ fqdn, ttl, c, type, ip ] = str.split(/\s+/)
    return new this.constructor({
      class  : c,
      type   : type,
      name   : fqdn,
      address: ip,
      ttl    : parseInt(ttl, 10),
    })
  }

  compress (val) {
    return val
      .replace(/\b(?:0+:){2,}/, ':')  // compress all zero
      .split(':')
      .map(o => o.replace(/\b0+/g, '')) // strip leading zero
      .join(':')
  }

  expand (val, delimiter) {
    if (delimiter === undefined) delimiter = ':'

    const colons = val.match(/:/g)
    if (colons && colons.length < 7) {
      // console.log(`AAAA: restoring compressed colons`)
      val = val.replace(/::/, ':'.repeat(9 - colons.length))
    }

    // restore compressed leading zeros
    return val.split(':').map(s => s.padStart(4, 0)).join(delimiter)
  }

  /******  EXPORTERS   *******/
  toBind () {
    return `${this.getFields().map(f => this.get(f)).join('\t')}\n`
  }

  toTinydns () {
    // from AAAA notation (8 groups of 4 hex digits) to 16 escaped octals
    const rdata = TINYDNS.packHex(this.expand(this.get('address'), ''))

    return `:${this.get('name')}:28:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = AAAA
