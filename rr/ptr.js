
const RR = require('./index')

class PTR extends RR {
  constructor (obj) {
    super(obj)

    if (obj?.dname) {
      this.setDname(obj?.dname)
    }
    else if (obj?.rdata) { // Generic DNS packet content
      this.setDname(obj?.rdata)
    }
    else if (obj?.ptrdname) { // RFC 1035
      this.setDname(obj?.ptrdname)
    }
    else if (obj?.address) { // RFC 1035
      this.setDname(obj?.address)
    }
  }

  setDname (val) {
    if (!this.fullyQualified('PTR', 'dname', val)) return
    if (!this.validHostname('PTR', 'dname', val)) return

    this.set('dname', val)
  }

  toBind () {
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\tPTR\t${this.get('dname')}\n`
  }

  toTinydns () {
    return `^${this.get('name')}:${this.get('dname')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = PTR
