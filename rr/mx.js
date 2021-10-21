
const net = require('net')

const RR = require('./index')

class MX extends RR {
  constructor (opts) {
    super(opts)

    this.setAddress(opts?.address)
    this.setWeight(opts?.weight)
  }

  setAddress (val) {
    if (!val) throw new Error('MX: address is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`MX: address must be a FQDN: RFC 2181`)

    if (!this.fullyQualified('MX', 'address', val)) return
    if (!this.validHostname('MX', 'address', val)) return
    this.set('address', val)
  }

  setWeight (val) {
    if (!this.is16bitInt('MX', 'weight', val)) return
    this.set('weight', val)
  }

  toBind () {
    return `${this.get('name')} ${this.get('ttl')} ${this.get('class')}  MX  ${this.get('weight')}  ${this.get('address')}\n`
  }

  toTinydns () {
    return `@${this.get('name')}::${this.get('address')}:${this.get('weight')}:${this.get('ttl')}:${this.get('timestamp')}:${this.get('location')}\n`
  }
}

module.exports = MX
