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
    this.isString('NAPTR', 'flags', val)
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
    this.setTypedValue('fqdn', 'replacement', val)
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/
}
