import RR from '../rr.js'

export default class CAA extends RR {
  static typeName = 'CAA'
  static typeId = 257
  static RFCs = [6844, 8659, 9619]
  static rdataFields = [
    ['flags', 'u8'],
    ['tag', 'charstr'],
    ['value', 'qstr'],
  ]
  static tags = ['security']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags(val) {
    this.is8bitInt('CAA', 'flags', val)

    if (!this.getFlagsOptions().has(val)) {
      this.throwHelp(`CAA flags ${val} not recognized`)
    }

    this.set('flags', val)
  }

  getFlagsOptions() {
    return new Map([
      [0, 'Non Critical'],
      [128, 'Critical'],
    ])
  }

  setTag(val) {
    if (typeof val !== 'string' || val.length < 1 || /[^a-z0-9]/.test(val))
      this.throwHelp(`CAA tag must be a sequence of ASCII letters and numbers in lowercase`)

    if (!this.getTagOptions().has(val)) {
      this.throwHelp(`CAA tag ${val} not recognized`)
    }
    this.set('tag', val)
  }

  getTagOptions() {
    return new Map([['issue'], ['issuewild'], ['iodef']])
  }

  setValue(val) {
    if (this.get('tag') === 'iodef') {
      const iodefSchemes = ['mailto:', 'http:', 'https:']
      if (!iodefSchemes.filter((s) => val.startsWith(s)).length) {
        this.throwHelp(`CAA value must have valid iodefScheme prefix`)
      }
    }

    this.set('value', val)
  }

  getDescription() {
    return 'Certification Authority Authorization'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'CAA',
      flags: 0,
      tag: 'issue',
      value: 'http://letsencrypt.org',
    }
  }

  /******  EXPORTERS   *******/
}
