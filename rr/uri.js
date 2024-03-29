import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class URI extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('URI', 'priority', val)

    this.set('priority', val)
  }

  setWeight(val) {
    this.is16bitInt('URI', 'weight', val)

    this.set('weight', val)
  }

  setTarget(val) {
    if (!val) this.throwHelp(`URI: target is required`)

    this.set('target', val)
  }

  /******  IMPORTERS   *******/
  fromTinydns(opts) {
    // URI via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = opts.tinyline.substring(1).split(':')
    if (n != 256) this.throwHelp('URI fromTinydns, invalid n')

    return new URI({
      type: 'URI',
      owner: this.fullyQualify(fqdn),
      priority: TINYDNS.octalToUInt16(rdata.substring(0, 8)),
      weight: TINYDNS.octalToUInt16(rdata.substring(8, 16)),
      target: TINYDNS.octalToChar(rdata.substring(16)),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind(opts) {
    // test.example.com  3600  IN  URI  priority, weight, target
    const [owner, ttl, c, type, priority, weight, target] =
      opts.bindline.split(/\s+/)
    return new URI({
      class: c,
      type: type,
      owner,
      priority: parseInt(priority, 10),
      weight: parseInt(weight, 10),
      target: target.replace(/^"|"$/g, ''),
      ttl: parseInt(ttl, 10),
    })
  }

  /******  MISC   *******/
  getDescription() {
    return 'URI'
  }

  getRdataFields(arg) {
    return ['priority', 'weight', 'target']
  }

  getRFCs() {
    return [7553]
  }

  getTypeId() {
    return 256
  }

  getQuotedFields() {
    return ['target']
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    let rdata = ''

    for (const e of ['priority', 'weight']) {
      rdata += TINYDNS.UInt16toOctal(this.get(e))
    }

    rdata += TINYDNS.escapeOctal(dataRe, this.get('target'))
    return this.getTinydnsGeneric(rdata)
  }
}
