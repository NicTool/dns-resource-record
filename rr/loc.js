
const RR = require('./index')

class LOC extends RR {
  constructor (opts) {
    super(opts)

    this.setAddress(opts?.address)
  }

  setAddress (val) {
    if (!val) throw new Error('LOC: address is required')

    // todo: validate this with https://datatracker.ietf.org/doc/html/rfc1876
    this.set('address', val)
  }

  getRFCs () {
    return [ 1876 ]
  }

  toBind () {
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\tLOC\t${this.get('address')}\n`
  }
}

module.exports = LOC
