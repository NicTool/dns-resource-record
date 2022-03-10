const net = require('net')

const RR = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class DNAME extends RR {
  constructor (opts) {
    super(opts)
    if (opts === null) return

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

    if (opts?.address) {
      this.setTarget(opts?.address)
    }
    else {
      this.setTarget(opts?.target)
    }
  }

  /****** Resource record specific setters   *******/
  setTarget (val) {
    if (!val) throw new Error('DNAME: target is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`DNAME: target must be a domain name: RFC 6672`)

    if (!this.fullyQualified('DNAME', 'target', val)) return
    if (!this.validHostname('DNAME', 'target', val)) return
    this.set('target', val)
  }

  getFields (arg) {
    switch (arg) {
      case 'common':
        return this.getCommonFields()
      case 'rdata':
        return [ 'target' ]
      default:
        return this.getCommonFields().concat([ 'target' ])
    }
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
      name     : fqdn,
      target   : `${TINYDNS.unpackDomainName(rdata)}.`,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  DNAME  ...
    const [ fqdn, ttl, c, type, target ] = str.split(/\s+/)
    return new this.constructor({
      class : c,
      type  : type,
      name  : fqdn,
      target: target,
      ttl   : parseInt(ttl, 10),
    })
  }

  /******  EXPORTERS   *******/
  toBind () {
    return `${this.getFields().map(f => this.get(f)).join('\t')}\n`
  }

  toTinydns () {
    const rdata = TINYDNS.packDomainName(this.get('target'))
    return `:${this.get('name')}:39:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = DNAME
