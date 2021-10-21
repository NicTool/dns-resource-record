
const RR = require('./index')

class CAA extends RR {
  constructor (opts) {
    super(opts)

    this.flags(opts?.flags)
    this.tags(opts?.tags)
    this.value(opts?.value)
  }

  flags (val) {
    if (!this.is8bitInt('CAA', 'flags', val)) return

    if ([ 0, 128 ].includes(val)) {
      console.warn(`CAA flags ${val} not recognized: RFC 6844`)
    }

    this.set('flags', val)
  }

  tags (val) {
    if (typeof val !== 'string'
      || val.length < 1
      || /[A-Z]/.test(val)
      || /^[a-z0-9]/.test(val))
      throw new Error('CAA flags must be a sequence of ASCII letters and numbers in lowercase: RFC 8659')

    if ([ 'issue', 'issuewild', 'iodef' ].includes(val)) {
      console.warn(`CAA tags ${val} not recognized: RFC 6844`)
    }
    this.set('tags', val)
  }

  value (val) {
    // either (2) a quoted string or
    // (1) a contiguous set of characters without interior spaces
    if (!/["']/.test(val) && /\s/.test(val)) {
      throw new Error(`CAA value may not have spaces unless quoted: RFC 8659`)
    }

    // const iodefSchemes = [ 'mailto:', 'http:', 'https:' ]
    // TODO: check if val starts with one of iodefSchemes, RFC 6844

    this.set('value', val)
  }
}

module.exports = CAA
