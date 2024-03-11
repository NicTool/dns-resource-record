import RR from '../rr.js'

export default class NS extends RR {
  constructor(opts) {
    super(opts)
    if (opts === null) return
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

  getRdataFields(arg) {
    return ['dname']
  }

  getRFCs() {
    return [1035]
  }

  getTypeId() {
    return 2
  }

  /******  IMPORTERS   *******/
  fromTinydns(opts) {
    // &fqdn:ip:x:ttl:timestamp:lo
    // eslint-disable-next-line no-unused-vars
    const [fqdn, ip, dname, ttl, ts, loc] = opts.tinyline
      .substring(1)
      .split(':')

    return new NS({
      type: 'NS',
      owner: this.fullyQualify(fqdn),
      dname: this.fullyQualify(
        /\./.test(dname) ? dname : `${dname}.ns.${fqdn}`,
      ),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind(opts) {
    // test.example.com  3600  IN  NS dname
    const [owner, ttl, c, type, dname] = opts.bindline.split(/\s+/)

    return new NS({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      dname: dname,
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.getFQDN('dname', zone_opts)}\n`
  }

  toTinydns() {
    return `&${this.getTinyFQDN('owner')}::${this.getTinyFQDN('dname')}:${this.getTinydnsPostamble()}\n`
  }
}
