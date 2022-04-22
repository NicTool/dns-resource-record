
import RR from '../rr.js'

export default class PTR extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setDname (val) {
    this.isFullyQualified('PTR', 'dname', val)
    this.isValidHostname('PTR', 'dname', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('dname', val.toLowerCase())
  }

  getDescription () {
    return 'Pointer'
  }

  getRdataFields (arg) {
    return [ 'dname' ]
  }

  getRFCs () {
    return [ 1035 ]
  }

  getTypeId () {
    return 12
  }

  /******  IMPORTERS   *******/
  fromTinydns (opts) {
    // ^fqdn:p:ttl:timestamp:lo
    const [ fqdn, p, ttl, ts, loc ] = opts.tinyline.substring(1).split(':')

    return new PTR({
      owner    : this.fullyQualify(fqdn),
      ttl      : parseInt(ttl, 10),
      type     : 'PTR',
      dname    : this.fullyQualify(p),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (opts) {
    // test.example.com  3600  IN  PTR  dname
    const [ owner, ttl, c, type, dname ] = opts.bindline.split(/\s+/)
    return new PTR({
      owner,
      ttl  : parseInt(ttl, 10),
      class: c,
      type : type,
      dname: dname,
    })
  }

  /******  EXPORTERS   *******/
  toTinydns () {
    return `^${this.getTinyFQDN('owner')}:${this.getTinyFQDN('dname')}:${this.getTinydnsPostamble()}\n`
  }
}
