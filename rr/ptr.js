
const RR = require('./index')

class PTR extends RR {
  constructor (obj) {
    super(obj)

    if (obj?.dname) {
      this.dname(obj?.dname)
    }
    else if (obj?.rdata) { // Generic DNS packet content
      this.dname(obj?.rdata)
    }
    else if (obj?.ptrdname) { // RFC 1035
      this.dname(obj?.ptrdname)
    }
  }

  dname (val) {
    if (!this.fullyQualified('PTR', 'dname', val)) return
    if (!this.validHostname('PTR', 'dname', val)) return

    this.set('dname', val)
  }
}

module.exports = PTR
