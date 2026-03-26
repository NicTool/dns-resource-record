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

  getTags() {
    return ['obsolete']
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

  getCanonical() {
    return {
      owner: 'test.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HINFO',
      cpu: 'DEC-2060',
      os: 'TOPS20',
    }
  }

  getQuotedFields() {
    return ['cpu', 'os']
  }

  /******  IMPORTERS   *******/
  fromBind({ bindline }) {
    // test.example.com  3600  IN  HINFO   DEC-2060 TOPS20
    const regex =
      /^(?<owner>\S+)\s+(?<ttl>\d{1,10})\s+(?<class>IN)\s+(?<type>HINFO)\s+(?:"(?<qCPU>[^"]*)"|(?<uCPU>\S+))\s+(?:"(?<qOS>[^"]*)"|(?<uOS>\S+))$/i

    const match = bindline.trim().match(regex)
    if (!match) this.throwHelp(`unable to parse HINFO: ${bindline}`)

    const { owner, ttl, class: c, type, qCPU, uCPU, qOS, uOS } = match.groups

    return new HINFO({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      cpu: qCPU ?? uCPU,
      os: qOS ?? uOS,
    })
  }

  fromTinydns({ tinyline }) {
    // HINFO via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, , rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    const [cpu, os] = [...TINYDNS.unpackString(rdata)]

    return new this.constructor({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'HINFO',
      cpu,
      os,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      [TINYDNS.packString(this.get('cpu')), TINYDNS.packString(this.get('os'))].join(''),
    )
  }
}
