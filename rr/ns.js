
const RR = require('./index').RR

class NS extends RR {
  constructor (opts) {
    super(opts)

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)

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
  fromTinydns (str) {
    // NS         =>  &fqdn:ip:x:ttl:timestamp:lo
    // eslint-disable-next-line no-unused-vars
    const [ fqdn, ip, dname, ttl, ts, loc ] = str.substring(1).split(':')

    return new this.constructor({
      type     : 'NS',
      name     : fqdn,
      dname    : dname,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
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
