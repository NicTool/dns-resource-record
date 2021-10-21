
const net = require('net')

const RR = require('./index')

class CNAME extends RR {
  constructor (opts) {
    super(opts)

    this.address(opts?.address)
  }

  address (val) {
    if (!val) throw new Error('CNAME: address is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`CNAME: address must be a FQDN: RFC 2181`)

    if (!this.fullyQualified('CNAME', 'address', val)) return
    if (!this.validHostname('CNAME', 'address', val)) return
    this.set('address', val)
  }

  toBind () {
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\tCNAME\t${this.get('address')}\n`
  }

  toTinydns () {
    return `C${this.get('name')}:${this.get('address')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = CNAME
