import RR from '../rr.js'

export default class SOA extends RR {
  static typeName = 'SOA'
  static typeId = 6
  static RFCs = [1035, 2308]
  static tinydnsType = 'Z'
  static rdataFields = [
    ['mname', 'fqdn'],
    ['rname', 'fqdn'],
    ['serial', 'u32'],
    ['refresh', 'u32'],
    ['retry', 'u32'],
    ['expire', 'u32'],
    ['minimum', 'u32'],
  ]
  static tags = ['common']

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
    this.isValidName('SOA', 'MNAME', val)
    this.isFullyQualified('SOA', 'MNAME', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('mname', this.lowercaseName(val))
  }

  setRname(val) {
    // RNAME (email of admin)  (escape . with \)
    this.isValidName('SOA', 'RNAME', val)
    this.isFullyQualified('SOA', 'RNAME', val)
    if (/@/.test(val)) this.throwHelp(`SOA rname replaces @ with a . (dot)`)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('rname', this.lowercaseName(val))
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
  fromTinydns({ tinyline }) {
    // Zfqdn:mname:rname:ser:ref:ret:exp:min:ttl:time:lo
    const [fqdn, mname, rname, ser, ref, ret, exp, min, ttl, ts, loc] = tinyline.slice(1).split(':')

    return new SOA({
      owner: this.fromTinyFQDN(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SOA',
      mname: this.fromTinyFQDN(mname),
      rname: this.fromTinyFQDN(rname),
      serial: parseInt(ser ?? this.default?.serial, 10),
      refresh: parseInt(ref, 10) || 16384,
      retry: parseInt(ret, 10) || 2048,
      expire: parseInt(exp, 10) || 1048576,
      minimum: parseInt(min, 10) || 2560,
      timestamp: parseInt(ts) || '',
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toMaraDNS() {
    this.assertClassIN('MaraDNS')
    return `${this.get('owner')}\t+${this.get('ttl')}\tSOA\t${this.getFields('rdata')
      .map((f) => this.getQuoted(f))
      .join('\t')} ~\n`
  }

  toTinydns() {
    return `Z${this.getTinyFQDN('owner')}:${this.getTinyFQDN('mname')}:${this.getTinyFQDN('rname')}:${this.getEmpty('serial')}:${this.getEmpty('refresh')}:${this.getEmpty('retry')}:${this.getEmpty('expire')}:${this.getEmpty('minimum')}:${this.getTinydnsPostamble()}\n`
  }
}
