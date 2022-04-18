
import net from 'net'

import RR from '../index.js'
import * as TINYDNS from '../lib/tinydns.js'

export default class SRV extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority (val) {
    this.is16bitInt('SRV', 'priority', val)

    this.set('priority', val)
  }

  setPort (val) {
    this.is16bitInt('SRV', 'port', val)

    this.set('port', val)
  }

  setWeight (val) {
    this.is16bitInt('SRV', 'weight', val)

    this.set('weight', val)
  }

  setTarget (val) {
    if (!val) throw new Error(`SRV: target is required, ${this.citeRFC()}`)

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`SRV: target must be a FQDN, ${this.citeRFC()}`)

    this.isFullyQualified('SRV', 'target', val)
    this.isValidHostname('SRV', 'target', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target', val.toLowerCase())
  }

  getDescription () {
    return 'Service'
  }

  getRdataFields (arg) {
    return [ 'priority', 'weight', 'port', 'target' ]
  }

  getRFCs () {
    return [ 2782 ]
  }

  getTypeId () {
    return 33
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
      owner    : this.fullyQualify(fqdn),
      ttl      : parseInt(ttl,    10),
      type     : 'SRV',
      priority : parseInt(pri,    10),
      weight   : parseInt(weight, 10),
      port     : parseInt(port,   10),
      target   : `${addr}.`,
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  SRV Priority Weight Port Target
    const [ owner, ttl, c, type, pri, weight, port, target ] = str.split(/\s+/)
    return new this.constructor({
      owner   : owner,
      ttl     : parseInt(ttl,    10),
      class   : c,
      type    : type,
      priority: parseInt(pri,    10),
      weight  : parseInt(weight, 10),
      port    : parseInt(port,   10),
      target  : target,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns () {

    let rdata = ''

    for (const e of [ 'priority', 'weight', 'port' ]) {
      rdata += TINYDNS.UInt16toOctal(this.get(e))
    }

    rdata += TINYDNS.packDomainName(this.get('target'))

    return this.getTinydnsGeneric(rdata)
  }
}
