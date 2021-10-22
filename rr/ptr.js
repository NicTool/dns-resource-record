
const RR = require('./index').RR

class PTR extends RR {
  constructor (obj) {
    super(obj)
    this.set('id', 12)

    if (obj?.address) { // RFC 1035
      this.setDname(obj?.address)
    }
    else if (obj?.ptrdname) {
      this.setDname(obj?.ptrdname)
    }
    else { // RFC 1035
      this.setDname(obj?.dname)
    }
  }

  /****** Resource record specific setters   *******/
  setDname (val) {
    if (!this.fullyQualified('PTR', 'dname', val)) return
    if (!this.validHostname('PTR', 'dname', val)) return

    this.set('dname', val)
  }

  getRFCs () {
    return [ 1035 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns () {
    // PTR        =>  ^ fqdn :  p : ttl:timestamp:lo
  }

  fromBind () {
    //
  }

  /******  EXPORTERS   *******/
  toBind () {
    const fields = [ 'name', 'ttl', 'class', 'type', 'dname' ]
    return `${fields.map(f => this.get(f)).join('\t')}\n`
  }

  toTinydns () {
    return `^${this.get('name')}:${this.get('dname')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = PTR
