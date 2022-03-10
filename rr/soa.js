
const RR = require('./index').RR

class SOA extends RR {
  constructor (opts) {
    super(opts)
    if (opts === null) return

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

    for (const f of this.getFields('rdata')) {
      const fnName = `set${f.charAt(0).toUpperCase() + f.slice(1)}`
      this[fnName](opts[f])
    }
  }

  /****** Resource record specific setters   *******/
  setMinimum (val) {
    // minimum (used for negative caching, since RFC 2308)
    // RFC 1912 sugggests 1-5 days
    // RIPE recommends 3600 (1 hour)
    if (!this.is32bitInt('SOA', 'minimum', val)) return

    this.set('minimum', val)
  }

  setMname (val) {
    // MNAME (primary NS)
    if (!this.validHostname('SOA', 'MNAME', val)) return
    if (!this.fullyQualified('SOA', 'MNAME', val)) return
    this.set('mname', val)
  }

  setRname (val) {
    // RNAME (email of admin)  (escape . with \)
    if (!this.validHostname('SOA', 'RNAME', val)) return
    if (!this.fullyQualified('SOA', 'RNAME', val)) return
    if (/@/.test(val)) throw new Error('SOA rname replaces @ with a . (dot).')
    this.set('rname', val)
  }

  setSerial (val) {
    if (!this.is32bitInt('SOA', 'serial', val)) return

    this.set('serial', val)
  }

  setRefresh (val) {
    // refresh (seconds after which to check with master for update)
    // RFC 1912 suggests 20 min to 12 hours
    // RIPE recommends 86400 (24 hours)
    if (!this.is32bitInt('SOA', 'refresh', val)) return

    this.set('refresh', val)
  }

  setRetry (val) {
    // seconds after which to retry serial # update
    // RIPE recommends 7200 seconds (2 hours)

    if (!this.is32bitInt('SOA', 'retry', val)) return

    this.set('retry', val)
  }

  setExpire (val) {
    // seconds after which secondary should drop zone if no master response
    // RFC 1912 suggests 2-4 weeks
    // RIPE suggests 3600000 (1,000 hours, 6 weeks)
    if (!this.is32bitInt('SOA', 'expire', val)) return

    this.set('expire', val)
  }

  getFields (arg) {
    switch (arg) {
      case 'common':
        return this.getCommonFields()
      case 'rdata':
        return [ 'mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum' ]
      default:
        return this.getCommonFields().concat([ 'mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum' ])
    }
  }

  getRFCs () {
    return [ 1035, 2308 ]
  }

  getTypeId () {
    return 6
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // Zfqdn:mname:rname:ser:ref:ret:exp:min:ttl:time:lo
    const [ fqdn, mname, rname, ser, ref, ret, exp, min, ttl, ts, loc ] = str.substring(1).split(':')

    return new this.constructor({
      type     : 'SOA',
      name     : fqdn,
      mname    : mname,
      rname    : rname,
      serial   : parseInt(ser, 10),
      refresh  : parseInt(ref, 10) || 16384,
      retry    : parseInt(ret, 10) || 2048,
      expire   : parseInt(exp, 10) || 1048576,
      minimum  : parseInt(min, 10) || 2560,
      ttl      : parseInt(ttl, 10),
      timestamp: parseInt(ts) || '',
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    /*
       $TTL 3600
       $ORIGIN example.com
       example.com  IN  SOA mname rname ( serial refresh retry expire minimum )
    */
    const [ , ttl, , fqdn, , c, type, mname, rname, , serial, refresh, retry, expire, minimum ] = str.split(/\s+/)

    const bits = {
      class  : c,
      type   : type,
      name   : fqdn.replace(/\.$/, ''),
      mname  : mname,
      rname  : rname,
      serial : parseInt(serial, 10),
      refresh: parseInt(refresh, 10),
      retry  : parseInt(retry, 10),
      expire : parseInt(expire, 10),
      minimum: parseInt(minimum, 10 ),
      ttl    : parseInt(ttl, 10),
    }
    // console.log(bits)
    return new this.constructor(bits)
  }

  /******  EXPORTERS   *******/
  toBind () {
    return `$TTL\t${this.get('ttl')}
$ORIGIN\t${this.get('name')}.
${this.get('name')}.\t${this.get('class')}\tSOA\t${this.get('mname')}\t${this.get('rname')} (
          ${this.get('serial')}
          ${this.get('refresh')}
          ${this.get('retry')}
          ${this.get('expire')}
          ${this.get('minimum')}
          )\n\n`
  }

  toTinydns () {
    return `Z${this.get('name')}:${this.get('mname')}:${this.getEmpty('rname')}:${this.getEmpty('serial')}:${this.getEmpty('refresh')}:${this.getEmpty('retry')}:${this.getEmpty('expire')}:${this.getEmpty('minimum')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = SOA
