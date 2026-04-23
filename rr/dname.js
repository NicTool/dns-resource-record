import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

export default class DNAME extends RR {
  static typeName = 'DNAME'
  static typeId = 39
  static RFCs = [2672, 6672]
  static rdataFields = [['target', 'fqdn']]

  constructor(opts) {
    super(opts)
  }

  getDescription() {
    return 'Delegation Name'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DNAME',
      target: 'example.net.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // DNAME via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 39) this.throwHelp('DNAME fromTinydns, invalid n')

    return new DNAME({
      type: 'DNAME',
      owner: this.fullyQualify(fqdn),
      target: TINYDNS.unpackDomainName(rdata)[0],
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    return this.wirePackDomain(this.get('target'))
  }

  toTinydns() {
    const rdata = TINYDNS.packDomainName(this.get('target'))
    return this.getTinydnsGeneric(rdata)
  }
}
