
const RR = require('./index')

class NS extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 2)

    if (!this.fullyQualified('NS', 'address', opts.address)) return
    if (!this.validHostname('NS', 'address', opts.address)) return
    this.set('address', opts.address)
  }

  getRFCs () {
    return [ 1035 ]
  }

  toBind () {
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\tNS\t${this.get('address')}\n`
  }

  toTinydns () {
    return `&${this.get('name')}::${this.get('address')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = NS
