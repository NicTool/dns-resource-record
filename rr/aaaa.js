import RR from '../rr.js'

export default class AAAA extends RR {
  static typeName = 'AAAA'
  static typeId = 28
  static RFCs = [3596, 5952]
  static rdataFields = [['address', 'ipv6']]
  static tags = ['common']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('AAAA: address is required')
    if (!this.isIPv6(val)) this.throwHelp(`AAAA: address must be IPv6 (${val})`)

    this.set('address', this.expandIPv6(val.toLowerCase())) // lower case: RFC 5952
  }

  getCompressed(val) {
    return this.compressIPv6(val ?? this.get('address'))
  }

  getDescription() {
    return 'Address IPv6'
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      address: '2001:0db8:0020:000a:0000:0000:0000:0004',
      class: 'IN',
      ttl: 3600,
      type: 'AAAA',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns(opts) {
    if (opts.tinyline[0] === ':') return this.fromTinydnsWire(opts)

    // AAAA     =>  3fqdn:ip:x:ttl:timestamp:lo
    // AAAA,PTR =>  6fqdn:ip:x:ttl:timestamp:lo
    const [fqdn, rdata, ttl, ts, loc] = opts.tinyline.slice(1).split(':')
    return new AAAA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'AAAA',
      address: rdata.match(/(.{4})/g).join(':'),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.getCompressed()}\n`
  }
}
