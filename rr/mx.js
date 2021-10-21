
const net = require('net')

const RR = require('./index')

class MX extends RR {
  constructor (opts) {
    super(opts)

    this.address(opts?.address)
    this.weight(opts?.weight)
  }

  address (val) {
    if (!val) throw new Error('MX: address is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`MX: address must be a FQDN: RFC 2181`)

    if (!this.fullyQualified('MX', 'address', val)) return
    if (!this.validHostname('MX', 'address', val)) return
    this.set('address', val)
  }

  weight (val) {
    if (!this.is16bitInt('MX', 'weight', val)) return
    this.set('weight', val)
  }
}

module.exports = MX
