import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class HINFO extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCpu(val) {
    if (val.length > 255) this.throwHelp('HINFO cpu cannot exceed 255 chars')
    this.set('cpu', val.replace(/^["']|["']$/g, ''))
  }

  setOs(val) {
    if (val.length > 255) this.throwHelp('HINFO os cannot exceed 255 chars')
    this.set('os', val.replace(/^["']|["']$/g, ''))
  }

  getDescription() {
    return 'Host Info'
  }

  getRdataFields(arg) {
    return ['cpu', 'os']
  }

  getRFCs() {
    return [1034, 1035, 8482]
  }

  getTypeId() {
    return 13
  }

  getQuotedFields() {
    return ['cpu', 'os']
  }

  /******  IMPORTERS   *******/
  fromBind(opts) {
    // test.example.com  3600  IN  HINFO   DEC-2060 TOPS20
    const regex = /^([\S]+)\s+([0-9]{1,10})\s+(IN)\s+(HINFO)\s+("[^"]+"|[\S]+)\s+("[^"]+"|[\S]+)/i
    const match = opts.bindline.trim().match(regex)
    if (!match) this.throwHelp(`unable to parse HINFO: ${opts.bindline}`)
    const [owner, ttl, c, type, cpu, os] = match.slice(1)

    return new HINFO({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      cpu,
      os,
    })
  }

  fromTinydns(opts) {
    // HINFO via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, , rdata, ttl, ts, loc] = opts.tinyline.substring(1).split(':')
    const [cpu, os] = [...TINYDNS.unpackString(rdata)]

    return new this.constructor({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'HINFO',
      cpu,
      os,
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      [TINYDNS.packString(this.get('cpu')), TINYDNS.packString(this.get('os'))].join(''),
    )
  }
}
