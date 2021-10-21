
const RR = require('./index')

class NS extends RR {
  constructor (opts) {
    super(opts)

    if (!this.fullyQualified('NS', 'address', opts.address)) return
    if (!this.validHostname('NS', 'address', opts.address)) return
    this.set('address', opts.address)
  }

  toBind () {
    return `${this.get('name')} ${this.get('ttl')} ${this.get('class')}  NS  ${this.get('address')}\n`
  }

  toTinydns () {
    return `&${this.get('name')}::${this.get('address')}:${this.get('ttl')}:${this.get('timestamp')}:${this.get('location')}\n`
  }
}

module.exports = NS
