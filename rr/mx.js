
const net = require('net')

const RR = require('./index').RR

class MX extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 15)

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

  getRFCs () {
    return [ 1035, 7505 ]
  }

  toBind () {
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\tMX\t${this.get('weight')}\t${this.get('address')}\n`
  }

  toTinydns () {
    return `@${this.get('name')}::${this.get('address')}:${this.get('weight')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = MX
