
const net = require('net')

const RR = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class SRV extends RR {
  constructor (opts) {
    super(opts)

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

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

  getFields () {
    return [ 'name', 'ttl', 'class', 'type', 'priority', 'weight', 'port', 'target' ]
  }

  getRFCs () {
    return [ 2782 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    let fqdn, addr, port, pri, weight, ttl, ts, loc, n, rdata

    if (str[0] === 'S') {
      // patched tinydns with S records
      [ fqdn, addr, port, pri, weight, ttl, ts, loc ] = str.substring(1).split(':')
    }
    else {
      // tinydns generic record format
      [ fqdn, n, rdata, ttl, ts, loc ] = str.substring(1).split(':')
      if (n != 33) throw new Error('SRV fromTinydns: invalid n')

      pri    = TINYDNS.octalToUInt16(rdata.substring(0, 8))
      weight = TINYDNS.octalToUInt16(rdata.substring(8, 16))
      port   = TINYDNS.octalToUInt16(rdata.substring(16, 24))
      addr   = TINYDNS.unpackDomainName(rdata.substring(24))
    }

    return new this.constructor({
      type     : 'SRV',
      name     : fqdn,
      target   : `${addr}.`,
      port     : parseInt(port,   10),
      priority : parseInt(pri,    10),
      weight   : parseInt(weight, 10),
      ttl      : parseInt(ttl,    10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind () {
    //
  }

  /******  EXPORTERS   *******/
  toBind () {
    return `${this.getFields().map(f => this.get(f)).join('\t')}\n`
  }

  toTinydns () {

    let rdata = ''

    for (const e of [ 'priority', 'weight', 'port' ]) {
      rdata += TINYDNS.UInt16toOctal(this.get(e))
    }

    rdata += TINYDNS.packDomainName(this.get('target'))

    return `:${this.get('name')}:33:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = SRV
