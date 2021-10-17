
const net = require('net')

class RR extends Map {

  constructor (opts) {
    super()

    this.class(opts?.class)
    this.name (opts?.name)
    this.ttl  (opts?.ttl)
    this.type (opts?.type)
  }

  class (c) {
    switch (c) {
      case 'IN':
      case undefined:
        this.set('class', 'IN')
        break
      case 'CS':
      case 'CH':
      case 'HS':
        this.set('class', c)
        break
      default:
        throw new Error(`invalid class ${c}`)
    }
  }

  name (n) {
    if (n === undefined) throw new Error(`name is required`)

    if (n.length < 1 || n.length > 255)
      throw new Error('Domain names must have 1-255 octets (characters): RFC 2181')

    this.hasValidLabels(n)

    this.set('name', n)
  }

  ttl (t) {

    if (t === undefined) return

    if (typeof t !== 'number') throw new Error(`TTL must be numeric (${typeof t})`)

    if (parseInt(t, 10) !== t) {
      throw new Error('TTL must be a an unsigned integer')
    }

    // RFC 1035, 2181
    if (!this.is32bitInt(this.name, 'TTL', t)) return

    this.set('ttl', t)
  }

  type (t) {
    this.set('type', t)
  }

  hasValidLabels (hostname) {
    for (const label of hostname.split('.')) {
      if (label.length < 1 || label.length > 63)
        throw new Error('Labels must have 1-63 octets (characters)')
    }
  }

  is16bitInt (type, field, value) {
    if (typeof value === 'number' && value >= 0 && value <= 65535) return true

    throw new Error(`$type} {field} must be a 16-bit integer (in the range 0-65535)`)
  }

  is32bitInt (type, field, value) {
    if (typeof value === 'number' && value >= 0 && value <= 2147483647) return true

    throw new Error(`$type} {field} must be a 32-bit integer (in the range 0-2147483647)`)
  }

  fullyQualified (type, blah, hostname) {
    if (hostname.slice(-1) === '.') return true

    throw new Error(`${type}: ${blah} must be fully qualified`)
  }

  validHostname (type, field, hostname) {
    if (!/[^a-zA-Z0-9\-._]/.test(hostname)) return true

    throw new Error(`${type}, ${field} has invalid hostname characters`)
  }
}

class A extends RR {
  constructor (opts) {
    super(opts)

    this.address(opts.address)
  }

  address (val) {
    if (!val) throw new Error('A: address is required')
    if (!net.isIPv4(val)) throw new Error('A address must be IPv4')
    this.set('address', val)
  }
}

class AAAA extends RR {
  constructor (opts) {
    super(opts)

    this.address(opts?.address)
  }

  address (val) {
    if (!val) throw new Error('AAAA: address is required')
    if (!net.isIPv6(val)) throw new Error('AAAA: address must be IPv6')
    this.set('address', val)
  }
}

class CNAME extends RR {
  constructor (opts) {
    super(opts)
  }

  address (val) {
    if (!val) throw new Error('CNAME: address is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`CNAME: address must be a FQDN: RFC 2181`)

    if (!this.fullyQualified('CNAME', 'address', val)) return
    if (!this.validHostname('CNAME', 'address', val)) return
    this.set('address', val)
  }
}

class MX extends RR {
  constructor (opts) {
    super(opts)

    this.address(opts?.address)
    this.weight(opts?.weight)
  }

  address (val) {
    if (!val) throw new Error('MX: address is required')

    if (net.isIPv4(val) || net.isIPv6(val))
      throw new Error(`MX: address must be a FQDN: RFC 2181`)

    if (!this.fullyQualified('MX', 'address', val)) return
    if (!this.validHostname('MX', 'address', val)) return
    this.set('address', val)
  }

  weight (val) {
    if (!this.is16bitInt('MX', 'weight', val)) return
    this.set('weight', val)
  }
}

class NS extends RR {
  constructor (opts) {
    super(opts)

    if (!this.fullyQualified('NS', 'address', opts.address)) return
    if (!this.validHostname('NS', 'address', opts.address)) return
    this.set('address', opts.address)
  }
}

class SOA extends RR {
  constructor (opts) {
    super(opts)

    // name is the zone name

    // ttl, minimum (used for negative caching, since RFC 2308)
    // RFC 1912 sugggests 1-5 days
    // RIPE recommends 3600 (1 hour)

    const fields = [ 'mname', 'rname', 'serial', 'refresh', 'retry', 'expire' ]
    for (const f of fields) {
      this[f](opts[f])
    }
  }

  // MNAME (primary NS)
  mname (val) {
    if (!this.validHostname('SOA', 'MNAME', val)) return
    if (!this.fullyQualified('SOA', 'MNAME', val)) return
    this.set('mname', val)
  }

  // RNAME (email of admin)  (escape . with \)
  rname (val) {
    if (!this.validHostname('SOA', 'RNAME', val)) return
    if (!this.fullyQualified('SOA', 'RNAME', val)) return
    if (/@/.test(val)) throw new Error('SOA RNAME replaces @ with a . (dot).')
    this.set('rname', val)
  }

  serial (val) {
    if (!this.is32bitInt('SOA', 'serial', val)) return

    this.set('serial', val)
  }

  refresh (val) {
    // refresh (seconds after which to check with master for update)
    // RFC 1912 suggests 20 min to 12 hours
    // RIPE recommends 86400 (24 hours)
    if (!this.is32bitInt('SOA', 'serial', val)) return

    this.set('refresh', val)
  }

  retry (val) {
    // seconds after which to retry serial # update
    // RIPE recommends 7200 seconds (2 hours)

    if (!this.is32bitInt('SOA', 'serial', val)) return

    this.set('retry', val)
  }

  expire (val) {
    // seconds after which secondary should drop zone if no master response
    // RFC 1912 suggests 2-4 weeks
    // RIPE suggests 3600000 (1,000 hours, 6 weeks)
    if (!this.is32bitInt('SOA', 'serial', val)) return

    this.set('expire', val)
  }
}

class TXT extends RR {
  constructor (opts) {
    super(opts)

    this.address(opts?.address)
  }

  address (val) {
    this.set('address', val)
  }
}

module.exports.A    = A
module.exports.AAAA = AAAA
module.exports.CNAME = CNAME
module.exports.MX   = MX
module.exports.NS   = NS
module.exports.SOA  = SOA
module.exports.TXT  = TXT

// module.exports.CAA = CAA
// module.exports.DNAME = DNAME
// module.exports.LOC = LOC
// module.exports.NAPTR = NAPTR
// module.exports.SSHFP = SSHFP
// module.exports.SRV = SRV
// module.exports.URI = URI