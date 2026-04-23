import RR from '../rr.js'

export default class NS extends RR {
  static typeName = 'NS'
  static typeId = 2
  static RFCs = [1035]
  static tinydnsType = '&'
  static rdataFields = [['dname', 'fqdn']]
  static tags = ['common']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setDname(val) {
    if (!val) this.throwHelp(`NS: dname is required`)

    this.isFullyQualified('NS', 'dname', val)
    this.isValidHostname('NS', 'dname', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('dname', val.toLowerCase())
  }

  getDescription() {
    return 'Name Server'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NS',
      dname: 'ns1.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // &fqdn:ip:x:ttl:timestamp:lo
    const [fqdn, _ip, dname, ttl, ts, loc] = tinyline.slice(1).split(':')

    return new NS({
      type: 'NS',
      owner: this.fullyQualify(fqdn),
      dname: this.fullyQualify(/\./.test(dname) ? dname : `${dname}.ns.${fqdn}`),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return this.wirePackDomain(this.get('dname'))
  }

  toTinydns() {
    return `&${this.getTinyFQDN('owner')}::${this.getTinyFQDN('dname')}:${this.getTinydnsPostamble()}\n`
  }
}
