const net = require('net')

const RR = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class DNAME extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 39)

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

  getRFCs () {
    return [ 2672, 6672 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns () {
    //
  }

  fromBind () {
    //
  }

  /******  EXPORTERS   *******/
  toBind () {
    const fields = [ 'name', 'ttl', 'class', 'type', 'target' ]
    return `${fields.map(f => this.get(f)).join('\t')}\n`
  }

  toTinydns () {
    const rdata = TINYDNS.packDomainName(this.get('target'))
    return `:${this.get('name')}:39:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = DNAME
