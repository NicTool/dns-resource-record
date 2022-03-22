
const net = require('net')

const RR = require('./index').RR

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
    this.set('cname', val)
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
      type     : 'CNAME',
      name     : this.fullyQualify(fqdn),
      cname    : p,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  CNAME  ...
    const [ fqdn, ttl, c, type, cname ] = str.split(/\s+/)
    return new this.constructor({
      class: c,
      type : type,
      name : fqdn,
      cname: cname,
      ttl  : parseInt(ttl, 10),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns () {
    return `C${this.getTinyFQDN('name')}:${this.get('cname')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = CNAME
