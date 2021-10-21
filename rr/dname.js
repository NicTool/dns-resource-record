const net = require('net')

const RR = require('./index')

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

  toBind () {
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\tDNAME\t${this.get('target')}\n`
  }
}

module.exports = DNAME
