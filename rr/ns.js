
import RR from '../index.js'

export default class NS extends RR {
  constructor (opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setDname (val) {
    if (!val) throw new Error(`NS: dname is required, ${this.citeRFC()}`)

    this.isFullyQualified('NS', 'dname', val)
    this.isValidHostname('NS', 'dname', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('dname', val.toLowerCase())
  }

  getDescription () {
    return 'Name Server'
  }

  getRdataFields (arg) {
    return [ 'dname' ]
  }

  getRFCs () {
    return [ 1035 ]
  }

  getTypeId () {
    return 2
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // &fqdn:ip:x:ttl:timestamp:lo
    // eslint-disable-next-line no-unused-vars
    const [ fqdn, ip, dname, ttl, ts, loc ] = str.substring(1).split(':')

    return new this.constructor({
      type     : 'NS',
      owner    : this.fullyQualify(fqdn),
      dname    : this.fullyQualify(/\./.test(dname) ? dname : `${dname}.ns.${fqdn}`),
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  NS dname
    const [ owner, ttl, c, type, dname ] = str.split(/\s+/)

    return new this.constructor({
      owner,
      ttl  : parseInt(ttl, 10),
      class: c,
      type : type,
      dname: dname,
    })
  }

  /******  EXPORTERS   *******/
  toBind (zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.getFQDN('dname', zone_opts)}\n`
  }

  toTinydns () {
    return `&${this.getTinyFQDN('owner')}::${this.getTinyFQDN('dname')}:${this.getTinydnsPostamble()}\n`
  }
}
