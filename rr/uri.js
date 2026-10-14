import RR from '../rr.js'

export default class URI extends RR {
  static typeName = 'URI'
  static typeId = 256
  static RFCs = [7553]
  static rdataFields = [
    ['priority', 'u16'],
    ['weight', 'u16'],
    ['target', 'qstr'],
  ]

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

  /******  MISC   *******/
  getDescription() {
    return 'URI'
  }

  getCanonical() {
    return {
      owner: 'www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'URI',
      priority: 10,
      weight: 10,
      target: 'http://www.example.com/',
    }
  }

  /******  EXPORTERS   *******/
}
