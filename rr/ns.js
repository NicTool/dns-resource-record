
const RR = require('./index').RR

class NS extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 2)

    if (opts?.address) {
      this.setDname(opts?.address)
    }
    else if (opts?.nsdname) {
      this.setDname(opts?.nsdname)
    }
    else {
      this.setDname(opts?.dname)
    }
  }

  /****** Resource record specific setters   *******/
  setDname (val) {
    if (!val) throw new Error('NS: dname is required')

    if (!this.fullyQualified('NS', 'dname', val)) return
    if (!this.validHostname('NS', 'dname', val)) return

    this.set('dname', val)
  }

  getRFCs () {
    return [ 1035 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns () {
    // NS         =>  & fqdn : ip : x:ttl:timestamp:lo
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
    return `&${this.get('name')}::${this.get('dname')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = NS
