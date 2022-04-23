
import RR from '../rr.js'

export default class SOA extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setMinimum (val) {
    // minimum (used for negative caching, since RFC 2308)
    // RFC 1912 sugggests 1-5 days
    // RIPE recommends 3600 (1 hour)
    this.is32bitInt('SOA', 'minimum', val)

    this.set('minimum', val)
  }

  setMname (val) {
    // MNAME (primary NS)
    this.isValidHostname('SOA', 'MNAME', val)
    this.isFullyQualified('SOA', 'MNAME', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('mname', val.toLowerCase())
  }

  setRname (val) {
    // RNAME (email of admin)  (escape . with \)
    this.isValidHostname('SOA', 'RNAME', val)
    this.isFullyQualified('SOA', 'RNAME', val)
    if (/@/.test(val)) throw new Error(`SOA rname replaces @ with a . (dot), ${this.citeRFC()}`)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('rname', val.toLowerCase())
  }

  setSerial (val) {
    this.is32bitInt('SOA', 'serial', val)

    this.set('serial', val)
  }

  setRefresh (val) {
    // refresh (seconds after which to check with master for update)
    // RFC 1912 suggests 20 min to 12 hours
    // RIPE recommends 86400 (24 hours)
    this.is32bitInt('SOA', 'refresh', val)

    this.set('refresh', val)
  }

  setRetry (val) {
    // seconds after which to retry serial # update
    // RIPE recommends 7200 seconds (2 hours)

    this.is32bitInt('SOA', 'retry', val)

    this.set('retry', val)
  }

  setExpire (val) {
    // seconds after which secondary should drop zone if no master response
    // RFC 1912 suggests 2-4 weeks
    // RIPE suggests 3600000 (1,000 hours, 6 weeks)
    this.is32bitInt('SOA', 'expire', val)

    this.set('expire', val)
  }

  getDescription () {
    return 'Start Of Authority'
  }

  getRdataFields (arg) {
    return [ 'mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum' ]
  }

  getRFCs () {
    return [ 1035, 2308 ]
  }

  getTypeId () {
    return 6
  }

  /******  IMPORTERS   *******/
  fromBind (opts) {
    // example.com TTL IN  SOA mname rname serial refresh retry expire minimum
    const [ owner, ttl, c, type, mname, rname, serial, refresh, retry, expire, minimum ] = opts.bindline.split(/[\s+]/)

    return new SOA({
      owner,
      ttl    : parseInt(ttl) || parseInt(minimum),
      class  : c,
      type,
      mname,
      rname,
      serial : parseInt(serial , 10),
      refresh: parseInt(refresh, 10),
      retry  : parseInt(retry  , 10),
      expire : parseInt(expire , 10),
      minimum: parseInt(minimum, 10),
    })
  }

  fromTinydns (opts) {
    // Zfqdn:mname:rname:ser:ref:ret:exp:min:ttl:time:lo
    const [ fqdn, mname, rname, ser, ref, ret, exp, min, ttl, ts, loc ] = opts.tinyline.substring(1).split(':')

    return new SOA({
      owner    : this.fullyQualify(fqdn),
      ttl      : parseInt(ttl, 10),
      type     : 'SOA',
      mname    : this.fullyQualify(mname),
      rname    : this.fullyQualify(rname),
      serial   : parseInt(ser || opts.default?.serial, 10),
      refresh  : parseInt(ref, 10) || 16384,
      retry    : parseInt(ret, 10) || 2048,
      expire   : parseInt(exp, 10) || 1048576,
      minimum  : parseInt(min, 10) || 2560,
      timestamp: parseInt(ts) || '',
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  /******  EXPORTERS   *******/
  toBind (zone_opts) {
    const numFields = [ 'serial', 'refresh', 'retry', 'expire', 'minimum' ]
    return `${this.getFQDN('owner', zone_opts)}\t${this.get('ttl')}\t${this.get('class')}\tSOA\t${this.getFQDN('mname', zone_opts)}\t${this.getFQDN('rname', zone_opts)}${numFields.map(f => '\t' + this.get(f) ).join('')}\n`
  }

  toMaraDNS () {
    return `${this.get('owner')}\t SOA\t${this.getRdataFields().map(f => this.getQuoted(f)).join('\t')} ~\n`
  }

  toTinydns () {
    return `Z${this.getTinyFQDN('owner')}:${this.getTinyFQDN('mname')}:${this.getTinyFQDN('rname')}:${this.getEmpty('serial')}:${this.getEmpty('refresh')}:${this.getEmpty('retry')}:${this.getEmpty('expire')}:${this.getEmpty('minimum')}:${this.getTinydnsPostamble()}\n`
  }
}
