
const net = require('net')

const RR = require('./index').RR

class CNAME extends RR {
  constructor (opts) {
    super(opts)

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

    this.set('id', 5)
    this.setCname(opts?.cname)
  }

  /****** Resource record specific setters   *******/
  setCname (val) {
    // A <domain-name> which specifies the canonical or primary
    // name for the owner.  The owner name is an alias.

    if (!val) throw new Error('CNAME: cname is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`CNAME: cname must be a FQDN: RFC 2181`)

    if (!this.fullyQualified('CNAME', 'cname', val)) return
    if (!this.validHostname('CNAME', 'cname', val)) return
    this.set('cname', val)
  }

  getFields () {
    return [ 'name', 'ttl', 'class', 'type', 'cname' ]
  }

  getRFCs () {
    return [ 1035, 2181 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // Cfqdn:p:ttl:timestamp:lo
    const [ fqdn, p, ttl, ts, loc ] = str.substring(1).split(':')

    return new this.constructor({
      type     : 'CNAME',
      name     : fqdn,
      cname    : p,
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
    return `C${this.get('name')}:${this.get('cname')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = CNAME
