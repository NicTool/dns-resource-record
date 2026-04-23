import RR from '../rr.js'

export default class SOA extends RR {
  static typeName = 'SOA'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setMinimum(val) {
    // minimum (used for negative caching, since RFC 2308)
    // RFC 1912 sugggests 1-5 days
    // RIPE recommends 3600 (1 hour)
    this.is32bitInt('SOA', 'minimum', val)

    this.set('minimum', val)
  }

  setMname(val) {
    // MNAME (primary NS)
    this.isValidHostname('SOA', 'MNAME', val)
    this.isFullyQualified('SOA', 'MNAME', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('mname', val.toLowerCase())
  }

  setRname(val) {
    // RNAME (email of admin)  (escape . with \)
    this.isValidHostname('SOA', 'RNAME', val)
    this.isFullyQualified('SOA', 'RNAME', val)
    if (/@/.test(val)) this.throwHelp(`SOA rname replaces @ with a . (dot)`)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('rname', val.toLowerCase())
  }

  setSerial(val) {
    this.is32bitInt('SOA', 'serial', val)

    this.set('serial', val)
  }

  setRefresh(val) {
    // refresh (seconds after which to check with master for update)
    // RFC 1912 suggests 20 min to 12 hours
    // RIPE recommends 86400 (24 hours)
    this.is32bitInt('SOA', 'refresh', val)

    this.set('refresh', val)
  }

  setRetry(val) {
    // seconds after which to retry serial # update
    // RIPE recommends 7200 seconds (2 hours)

    this.is32bitInt('SOA', 'retry', val)

    this.set('retry', val)
  }

  setExpire(val) {
    // seconds after which secondary should drop zone if no master response
    // RFC 1912 suggests 2-4 weeks
    // RIPE suggests 3600000 (1,000 hours, 6 weeks)
    this.is32bitInt('SOA', 'expire', val)

    this.set('expire', val)
  }

  getDescription() {
    return 'Start Of Authority'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum']
  }

  getRFCs() {
    return [1035, 2308]
  }

  getTypeId() {
    return 6
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SOA',
      mname: 'ns1.example.com.',
      rname: 'admin.example.com.',
      serial: 2023051001,
      refresh: 7200,
      retry: 3600,
      expire: 1209600,
      minimum: 3600,
    }
  }

  /******  IMPORTERS   *******/
  fromBind(opts) {
    const { owner, ttl, cls, rdata } = opts
    const [mname, rname, serial, refresh, retry, expire, minimum] = rdata

    return new SOA({
      owner,
      ttl: ttl || parseInt(minimum, 10),
      class: cls,
      type: 'SOA',
      mname,
      rname,
      serial: parseInt(serial, 10),
      refresh: parseInt(refresh, 10),
      retry: parseInt(retry, 10),
      expire: parseInt(expire, 10),
      minimum: parseInt(minimum, 10),
    })
  }

  fromTinydns({ tinyline }) {
    // Zfqdn:mname:rname:ser:ref:ret:exp:min:ttl:time:lo
    const [fqdn, mname, rname, ser, ref, ret, exp, min, ttl, ts, loc] = tinyline.slice(1).split(':')

    return new SOA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SOA',
      mname: this.fullyQualify(mname),
      rname: this.fullyQualify(rname),
      serial: parseInt(ser ?? this.default?.serial, 10),
      refresh: parseInt(ref, 10) || 16384,
      retry: parseInt(ret, 10) || 2048,
      expire: parseInt(exp, 10) || 1048576,
      minimum: parseInt(min, 10) || 2560,
      timestamp: parseInt(ts) || '',
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const { fqdn: mname, end: e1 } = this.wireUnpackDomain(rdata, 0)
    const { fqdn: rname, end: e2 } = this.wireUnpackDomain(rdata, e1)
    const dv = new DataView(rdata.buffer, rdata.byteOffset + e2)
    return new SOA({
      owner,
      ttl,
      class: cls,
      type: 'SOA',
      mname,
      rname,
      serial: dv.getUint32(0),
      refresh: dv.getUint32(4),
      retry: dv.getUint32(8),
      expire: dv.getUint32(12),
      minimum: dv.getUint32(16),
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    const numFields = ['serial', 'refresh', 'retry', 'expire', 'minimum']
    return `${this.getFQDN('owner', zone_opts)}\t${this.get('ttl')}\t${this.get('class')}\tSOA\t${this.getFQDN('mname', zone_opts)}\t${this.getFQDN('rname', zone_opts)}${numFields.map((f) => '\t' + this.get(f)).join('')}\n`
  }

  toMaraDNS() {
    return `${this.get('owner')}\t SOA\t${this.getRdataFields()
      .map((f) => this.getQuoted(f))
      .join('\t')} ~\n`
  }

  getWireRdata() {
    const mname = this.wirePackDomain(this.get('mname'))
    const rname = this.wirePackDomain(this.get('rname'))
    const result = new Uint8Array(mname.length + rname.length + 20)
    let offset = 0
    result.set(mname, offset)
    offset += mname.length
    result.set(rname, offset)
    offset += rname.length
    const view = new DataView(result.buffer, offset)
    view.setUint32(0, this.get('serial'))
    view.setUint32(4, this.get('refresh'))
    view.setUint32(8, this.get('retry'))
    view.setUint32(12, this.get('expire'))
    view.setUint32(16, this.get('minimum'))
    return result
  }

  toTinydns() {
    return `Z${this.getTinyFQDN('owner')}:${this.getTinyFQDN('mname')}:${this.getTinyFQDN('rname')}:${this.getEmpty('serial')}:${this.getEmpty('refresh')}:${this.getEmpty('retry')}:${this.getEmpty('expire')}:${this.getEmpty('minimum')}:${this.getTinydnsPostamble()}\n`
  }
}
