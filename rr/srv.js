
const net = require('net')

const sprintf = require('sprintf-js').sprintf

const RR = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class SRV extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 33)

    this.setPriority(opts?.priority)
    this.setWeight(opts?.weight)
    this.setPort(opts?.port)

    if (this?.address) {
      this.setTarget(opts?.address)
    }
    else {
      this.setTarget(opts?.target)
    }
  }

  setPriority (val) {
    if (!this.is16bitInt('SRV', 'priority', val)) return

    this.set('priority', val)
  }

  setPort (val) {
    if (!this.is16bitInt('SRV', 'port', val)) return

    this.set('port', val)
  }

  setWeight (val) {
    if (!this.is16bitInt('SRV', 'weight', val)) return

    this.set('weight', val)
  }

  setTarget (val) {
    if (!val) throw new Error('SRV: target is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`SRV: target must be a FQDN: RFC 2782`)

    if (!this.fullyQualified('SRV', 'target', val)) return
    if (!this.validHostname('SRV', 'target', val)) return
    this.set('target', val)
  }

  getRFCs () {
    return [ 2782 ]
  }

  toBind () {
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\tSRV\t${this.get('priority')}\t${this.get('weight')}\t${this.get('port')}\t${this.get('target')}\n`
  }

  toTinydns () {

    let rdata = ''

    for (const e of [ 'priority', 'weight', 'port' ]) {
      const pri = Buffer.alloc(2)
      pri.writeUInt16BE(this.get(e))
      rdata += sprintf('\\%03o', pri.readUInt8(0))
      rdata += sprintf('\\%03o', pri.readUInt8(1))
    }

    rdata += TINYDNS.packDomainName(this.get('target'))

    return `:${this.get('name')}:33:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = SRV
