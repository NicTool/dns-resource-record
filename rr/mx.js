import RR from '../rr.js'

export default class MX extends RR {
  static typeName = 'MX'
  static typeId = 15
  static RFCs = [1035, 2181, 7505]
  static tinydnsType = '@'
  static rdataFields = [
    ['preference', 'u16'],
    ['exchange', 'fqdn'],
  ]
  static tags = ['common']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPreference(val) {
    if (val === undefined) val = this?.default?.preference
    if (val === undefined) this.throwHelp('MX: preference is required')
    this.is16bitInt('MX', 'preference', val)
    this.set('preference', val)
  }

  setExchange(val) {
    this.setTypedValue('fqdn', 'exchange', val)
  }

  getDescription() {
    return 'Mail Exchanger'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 43200,
      class: 'IN',
      type: 'MX',
      preference: 10,
      exchange: 'mail.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // @fqdn:ip:x:dist:ttl:timestamp:lo
    const [owner, _ip, x, preference, ttl, ts, loc] = tinyline.slice(1).split(':')

    return new MX({
      type: 'MX',
      owner: this.fullyQualify(owner),
      exchange: this.fullyQualify(/\./.test(x) ? x : `${x}.mx.${owner}`),
      preference: parseInt(preference, 10) || 0,
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    const domain = this.wirePackDomain(this.get('exchange'))
    const result = new Uint8Array(2 + domain.length)
    new DataView(result.buffer).setUint16(0, this.get('preference'))
    result.set(domain, 2)
    return result
  }

  toTinydns() {
    return `@${this.getTinyFQDN('owner')}::${this.getTinyFQDN('exchange')}:${this.get('preference')}:${this.getTinydnsPostamble()}\n`
  }
}
