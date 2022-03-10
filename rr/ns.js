
const RR = require('./index').RR

class NS extends RR {
  constructor (opts) {
    super(opts)
    if (opts === null) return

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

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

  getFields (arg) {
    switch (arg) {
      case 'common':
        return this.getCommonFields()
      case 'rdata':
        return [ 'dname' ]
      default:
        return this.getCommonFields().concat([ 'dname' ])
    }
  }

  getRFCs () {
    return [ 1035 ]
  }

  getTypeId () {
    return 2
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // &fqdn:ip:x:ttl:timestamp:lo
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

  fromBind (str) {
    // test.example.com  3600  IN  NS dname
    const [ fqdn, ttl, c, type, dname ] = str.split(/\s+/)

    return new this.constructor({
      class: c,
      type : type,
      name : fqdn,
      dname: dname,
      ttl  : parseInt(ttl, 10),
    })
  }

  /******  EXPORTERS   *******/
  toTinydns () {
    return `&${this.get('name')}::${this.get('dname')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = NS
