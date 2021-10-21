
const RR = require('./index')

class LOC extends RR {
  constructor (opts) {
    super(opts)

    this.address(opts?.address)
  }

  address (val) {
    // todo: validate this with https://datatracker.ietf.org/doc/html/rfc1876
    this.set('address', val)
  }
}

module.exports = LOC
