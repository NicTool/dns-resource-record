
const net = require('net')

const RR = require('./index')

class A extends RR {
  constructor (opts) {
    super(opts)

    this.setAddress(opts.address)
  }

  setAddress (val) {
    if (!val) throw new Error('A: address is required')
    if (!net.isIPv4(val)) throw new Error('A address must be IPv4')
    this.set('address', val)
  }

  toBind () {
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\t${this.get('type')}\t${this.get('address')}\n`
  }

  toTinydns () {
    return `+${this.get('name')}:${this.get('address')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = A