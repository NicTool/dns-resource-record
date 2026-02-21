import RR from '../rr.js'

export default class KX extends RR {
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
    this.isValidHostname('KX', 'exchanger', val)

    this.set('exchanger', val.toLowerCase())
  }

  getDescription() {
    return 'Key Exchanger'
  }

  getRdataFields(arg) {
    return ['preference', 'exchanger']
  }

  getRFCs() {
    return [2230]
  }

  getTypeId() {
    return 36
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
  fromBind(opts) {
    // test.example.com  3600  IN  KX  preference exchanger
    const [owner, ttl, c, type, preference, exchanger] = opts.bindline.split(/\s+/)
    return new KX({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      preference: parseInt(preference, 10),
      exchanger,
    })
  }

  /******  EXPORTERS   *******/
}
