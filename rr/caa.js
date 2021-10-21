
const RR = require('./index')

class CAA extends RR {
  constructor (opts) {
    super(opts)

    this.setFlags(opts?.flags)
    this.setTags(opts?.tags)
    this.setValue(opts?.value)
  }

  setFlags (val) {
    if (!this.is8bitInt('CAA', 'flags', val)) return

    if (![ 0, 128 ].includes(val)) {
      console.warn(`CAA flags ${val} not recognized: RFC 6844`)
    }

    this.set('flags', val)
  }

  setTags (val) {
    if (typeof val !== 'string'
      || val.length < 1
      || /[A-Z]/.test(val)
      || /[^a-z0-9]/.test(val))
      throw new Error('CAA flags must be a sequence of ASCII letters and numbers in lowercase: RFC 8659')

    if (![ 'issue', 'issuewild', 'iodef' ].includes(val)) {
      console.warn(`CAA tags ${val} not recognized: RFC 6844`)
    }
    this.set('tags', val)
  }

  setValue (val) {
    // either (2) a quoted string or
    // (1) a contiguous set of characters without interior spaces
    if (!/["']/.test(val) && /\s/.test(val)) {
      throw new Error(`CAA value may not have spaces unless quoted: RFC 8659`)
    }

    // const iodefSchemes = [ 'mailto:', 'http:', 'https:' ]
    // TODO: check if val starts with one of iodefSchemes, RFC 6844

    this.set('value', val)
  }

  toBind () {
    let val = this.get('value')
    if (val[0] !== '"') val = `"${val}"` // add enclosing quotes
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\tCAA\t${this.get('flags')}\t${this.get('tags')}\t${val}\n`
  }
}

module.exports = CAA
