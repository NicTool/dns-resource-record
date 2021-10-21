const net = require('net')

const RR = require('./index')

class SRV extends RR {
  constructor (opts) {
    super(opts)

    this.priority(opts?.priority)
    this.weight(opts?.weight)
    this.port(opts?.port)
    this.target(opts?.target)
  }

  priority (val) {
    if (!this.is16bitInt('SRV', 'priority', val)) return

    this.set('priority', val)
  }

  port (val) {
    if (!this.is16bitInt('SRV', 'port', val)) return

    this.set('port', val)
  }

  weight (val) {
    if (!this.is16bitInt('SRV', 'weight', val)) return

    this.set('weight', val)
  }

  target (val) {

    if (!val) throw new Error('SRV: target is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`SRV: target must be a FQDN: RFC 2782`)

    if (!this.fullyQualified('SRV', 'target', val)) return
    if (!this.validHostname('SRV', 'target', val)) return
    this.set('target', val)
  }
}

module.exports = SRV
