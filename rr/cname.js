
const net = require('net')

const RR = require('./index').RR

class CNAME extends RR {
  constructor (opts) {
    super(opts)
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

  getRFCs () {
    return [ 1035, 2181 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns () {
    // CNAME      =>  C fqdn :  p : ttl:timestamp:lo
  }

  fromBind () {
    //
  }

  /******  EXPORTERS   *******/
  toBind () {
    const fields = [ 'name', 'ttl', 'class', 'type', 'cname' ]
    return `${fields.map(f => this.get(f)).join('\t')}\n`
  }

  toTinydns () {
    return `C${this.get('name')}:${this.get('cname')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = CNAME
