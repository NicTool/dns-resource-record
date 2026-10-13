import RR from '../rr.js'

export default class NAPTR extends RR {
  static typeName = 'NAPTR'
  static typeId = 35
  static RFCs = [2915, 3403, 4848]
  static rdataFields = [
    ['order', 'u16'],
    ['preference', 'u16'],
    ['flags', 'qcharstr'],
    ['service', 'qcharstr'],
    ['regexp', 'qcharstr'],
    ['replacement', 'fqdn'],
  ]

  constructor(opts) {
    super(opts)
  }

  getDescription() {
    return 'Naming Authority Pointer'
  }

  getCanonical() {
    return {
      owner: 'cid.urn.arpa.',
      ttl: 3600,
      class: 'IN',
      type: 'NAPTR',
      order: 100,
      preference: 10,
      flags: 'S',
      service: 'z3950+N2L+N2R',
      regexp: '',
      replacement: 'gatekeeper.example.com.',
    }
  }

  /****** Resource record specific setters   *******/
  setOrder(val) {
    this.is16bitInt('NAPTR', 'order', val)
    this.set('order', val)
  }

  setPreference(val) {
    this.is16bitInt('NAPTR', 'preference', val)
    this.set('preference', val)
  }

  setFlags(val) {
    if (!this.getFlagsOptions().has(val.toUpperCase())) this.throwHelp(`NAPTR flags are invalid`)

    this.set('flags', val.toUpperCase())
  }

  getFlagsOptions() {
    return new Map([[''], ['S'], ['A'], ['U'], ['P']])
  }

  setService(val) {
    this.set('service', val)
  }

  setRegexp(val) {
    this.set('regexp', val)
  }

  setReplacement(val) {
    this.set('replacement', val)
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/

  getWireRdata() {
    const enc = new TextEncoder()
    const flags = enc.encode(this.get('flags'))
    const service = enc.encode(this.get('service'))
    const regexp = enc.encode(this.get('regexp'))
    const replacementBytes = this.wirePackDomain(this.get('replacement'))

    const len = 4 + 1 + flags.length + 1 + service.length + 1 + regexp.length + replacementBytes.length
    const buf = new Uint8Array(len)
    const view = new DataView(buf.buffer)
    let pos = 0
    view.setUint16(pos, this.get('order'))
    pos += 2
    view.setUint16(pos, this.get('preference'))
    pos += 2
    buf[pos++] = flags.length
    buf.set(flags, pos)
    pos += flags.length
    buf[pos++] = service.length
    buf.set(service, pos)
    pos += service.length
    buf[pos++] = regexp.length
    buf.set(regexp, pos)
    pos += regexp.length
    buf.set(replacementBytes, pos)
    return buf
  }
}
