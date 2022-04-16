const net = require('net')

const RR = require('../index.js').RR
const TINYDNS = require('../lib/tinydns')

class DNAME extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTarget (val) {
    if (!val) throw new Error('DNAME: target is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`DNAME: target must be a domain name, ${this.citeRFC()}`)

    this.isFullyQualified('DNAME', 'target', val)
    this.isValidHostname('DNAME', 'target', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target', val.toLowerCase())
  }

  getDescription () {
    return 'Delegation Name'
  }

  getRdataFields (arg) {
    return [ 'target' ]
  }

  getRFCs () {
    return [ 2672, 6672 ]
  }

  getTypeId () {
    return 39
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // DNAME via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [ fqdn, n, rdata, ttl, ts, loc ] = str.substring(1).split(':')
    if (n != 39) throw new Error('DNAME fromTinydns, invalid n')

    return new this.constructor({
      type     : 'DNAME',
      owner    : this.fullyQualify(fqdn),
      target   : `${TINYDNS.unpackDomainName(rdata)}.`,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  DNAME  ...
    const [ owner, ttl, c, type, target ] = str.split(/\s+/)
    return new this.constructor({
      owner,
      ttl  : parseInt(ttl, 10),
      class: c,
      type,
      target,
    })
  }

  /******  EXPORTERS   *******/
  toTinydns () {
    const rdata = TINYDNS.packDomainName(this.get('target'))
    return this.getTinydnsGeneric(rdata)
  }
}

module.exports = DNAME
