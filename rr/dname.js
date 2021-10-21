const net = require('net')

const RR = require('./index')

class DNAME extends RR {
  constructor (opts) {
    super(opts)

    this.target(opts?.target)
  }

  target (val) {
    if (!val) throw new Error('DNAME: target is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`DNAME: target must be a domain name: RFC 6672`)

    if (!this.fullyQualified('DNAME', 'target', val)) return
    if (!this.validHostname('DNAME', 'target', val)) return
    this.set('target', val)
  }
}

module.exports = DNAME
