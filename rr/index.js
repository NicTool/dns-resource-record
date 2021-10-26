
// [...Array(128).keys()].map(n => { return String.fromCharCode(n) }).map(c => /[^0-9A-Za-z]/.test(c) ? c : 0)

const supportedTypes = [
  'A'    , 'AAAA', 'CAA'  , 'CNAME', 'DNAME',
  'LOC'  , 'MX'  , 'NAPTR', 'NS'   , 'PTR'  ,
  'SSHFP', 'SOA' , 'SPF'  , 'SRV'  , 'TXT'  , 'URI',
]

class RR extends Map {

  constructor (opts) {
    super()

    if (opts.default) this.default = opts.default

    if (opts.tinyline) return // pass through

    // tinydns specific
    this.setLocation(opts?.location)
    this.setTimestamp(opts?.timestamp)

    this.setName (opts?.name)
    this.setTtl  (opts?.ttl)
    this.setClass(opts?.class)
    this.setType (opts?.type)
  }

  setClass (c) {
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

  setLocation (l) {
    switch (l) {
      case undefined:
        return
      default:
        this.set('location', l)
    }
  }

  setTimestamp (l) {
    switch (l) {
      case undefined:
        return
      default:
        this.set('timestamp', l)
    }
  }

  setName (n) {
    if (n === undefined) throw new Error(`name is required`)

    if (n.length < 1 || n.length > 255)
      throw new Error('Domain names must have 1-255 octets (characters): RFC 2181')

    this.hasValidLabels(n)

    if (/\*/.test(n)) {
      if (!/^\*\./.test(n) && !/\.\*\./.test(n)) throw new Error('only *.something or * (by itself) is a valid wildcard')
    }

    this.set('name', n)
  }

  setTtl (t) {

    if (t === undefined) {
      if (this?.default?.ttl) {
        t = this.default.ttl
      }
      else {
        if ('SSHPF' === this.get('type')) return
        throw new Error('TTL is required, no default available')
      }
    }

    if (typeof t !== 'number') throw new Error(`TTL must be numeric (${typeof t})`)

    if (parseInt(t, 10) !== t) {
      throw new Error('TTL must be a an unsigned integer')
    }

    // RFC 1035, 2181
    if (!this.is32bitInt(this.name, 'TTL', t)) return

    this.set('ttl', t)
  }

  setType (t) {
    if (!supportedTypes.includes(t)) throw new Error(`type ${t} not supported (yet)`)
    this.set('type', t)
  }

  getEmpty (prop) {
    return this.get(prop) === undefined ? '' : this.get(prop)
  }

  getQuoted (prop) {
    if (/['"]/.test(this.get(prop)[0])) return this.get(prop) // already quoted
    return `"${this.get(prop)}"`
  }

  hasValidLabels (hostname) {
    for (const label of hostname.split('.')) {
      if (label.length < 1 || label.length > 63)
        throw new Error('Labels must have 1-63 octets (characters)')
    }
  }

  is8bitInt (type, field, value) {
    if (typeof value === 'number'
      && parseInt(value, 10) === value  // assure integer
      && value >= 0
      && value <= 255) return true

    throw new Error(`${type} ${field} must be a 8-bit integer (in the range 0-255)`)
  }

  is16bitInt (type, field, value) {
    if (typeof value === 'number'
      && parseInt(value, 10) === value  // assure integer
      && value >= 0
      && value <= 65535) return true

    throw new Error(`${type} ${field} must be a 16-bit integer (in the range 0-65535)`)
  }

  is32bitInt (type, field, value) {
    if (typeof value === 'number'
      && parseInt(value, 10) === value  // assure integer
      && value >= 0
      && value <= 2147483647) return true

    throw new Error(`${type} ${field} must be a 32-bit integer (in the range 0-2147483647)`)
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

module.exports = {
  RR,
}

for (const t of supportedTypes) {
  module.exports[t] = require(`./${t.toLowerCase()}`)
}