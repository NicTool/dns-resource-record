
const net = require('net')

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

  /****** Resource record specific setters   *******/
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

  /******  IMPORTERS   *******/
  fromTinydns () {
    //
  }

  fromBind () {
    //
  }

  /******  EXPORTERS   *******/
  toBind () {
    const fields = [ 'name', 'ttl', 'class', 'type', 'priority', 'weight', 'port', 'target' ]
    return `${fields.map(f => this.get(f)).join('\t')}\n`
  }

  toTinydns () {

    let rdata = ''

    for (const e of [ 'priority', 'weight', 'port' ]) {
      rdata += TINYDNS.UInt16AsOctal(this.get(e))
    }

    rdata += TINYDNS.packDomainName(this.get('target'))

    return `:${this.get('name')}:33:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = SRV
