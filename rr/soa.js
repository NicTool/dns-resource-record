
const RR = require('./index')

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

module.exports = SOA
