import RR from '../rr.js'

export default class KX extends RR {
  static typeName = 'KX'
  static typeId = 36
  static RFCs = [2230]
  static rdataFields = [
    ['preference', 'u16'],
    ['exchanger', 'fqdn'],
  ]

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPreference(val) {
    if (val === undefined) this.throwHelp('KX: preference is required')
    this.is16bitInt('KX', 'preference', val)
    this.set('preference', val)
  }

  setExchanger(val) {
    if (!val) this.throwHelp('KX: exchanger is required')

    this.isFullyQualified('KX', 'exchanger', val)
    this.isValidName('KX', 'exchanger', val)

    this.set('exchanger', this.lowercaseName(val))
  }

  getDescription() {
    return 'Key Exchanger'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'KX',
      preference: 10,
      exchanger: 'kx.example.com.',
    }
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/
}
