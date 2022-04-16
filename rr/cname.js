
const net = require('net')

const RR = require('../index.js').RR

class CNAME extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCname (val) {
    // A <domain-name> which specifies the canonical or primary
    // name for the owner.  The owner name is an alias.

    if (!val) throw new Error('CNAME: cname is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`CNAME: cname must be a FQDN: RFC 2181`)

    if (!this.isFullyQualified('CNAME', 'cname', val)) return
    if (!this.isValidHostname('CNAME', 'cname', val)) return

    // RFC 4034: letters in the DNS names are lower cased
    this.set('cname', val.toLowerCase())
  }

  getDescription () {
    return 'Canonical Name'
  }

  getRdataFields (arg) {
    return [ 'cname' ]
  }

  getRFCs () {
    return [ 1035, 2181 ]
  }

  getTypeId () {
    return 5
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // Cfqdn:p:ttl:timestamp:lo
    const [ fqdn, p, ttl, ts, loc ] = str.substring(1).split(':')

    return new this.constructor({
      owner    : this.fullyQualify(fqdn),
      ttl      : parseInt(ttl, 10),
      type     : 'CNAME',
      cname    : p,
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  CNAME  ...
    const [ owner, ttl, c, type, cname ] = str.split(/\s+/)
    return new this.constructor({
      owner,
      ttl  : parseInt(ttl, 10),
      class: c,
      type,
      cname,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns () {
    return `C${this.getTinyFQDN('owner')}:${this.get('cname')}:${this.getTinydnsPostamble()}\n`
  }
}

module.exports = CNAME
