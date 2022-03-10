
const RR = require('./index').RR

const TINYDNS = require('../lib/tinydns')

class TXT extends RR {
  constructor (opts) {
    super(opts)
    if (opts === null) return

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

    this.setData(opts?.data)
  }

  /****** Resource record specific setters   *******/
  setData (val) {
    this.set('data', val)
  }

  getFields (arg) {
    switch (arg) {
      case 'common':
        return this.getCommonFields()
      case 'rdata':
        return [ 'data' ]
      default:
        return this.getCommonFields().concat([ 'data' ])
    }
  }

  getRFCs () {
    return [ 1035 ]
  }

  getTypeId () {
    return 16
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    let fqdn, rdata, s, ttl, ts, loc
    // 'fqdn:s:ttl:timestamp:lo
    if (str[0] === "'") {
      [ fqdn, s, ttl, ts, loc ] = str.substring(1).split(':')
      rdata = TINYDNS.octalToChar(s)
    }
    else {
      [ fqdn, rdata, ttl, ts, loc ] = this.fromTinydnsGeneric(str)
    }

    return new this.constructor({
      type     : 'TXT',
      name     : fqdn,
      data     : rdata,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromTinydnsGeneric (str) {
    // generic: :fqdn:n:rdata:ttl:timestamp:location
    // eslint-disable-next-line prefer-const
    let [ fqdn, n, rdata, ttl, ts, loc ] = str.substring(1).split(':')
    if (n != 16) throw new Error('TXT fromTinydns, invalid n')

    rdata = TINYDNS.octalToChar(rdata)
    let s = ''
    let len = rdata[0].charCodeAt(0)
    let pos = 1
    while (pos < rdata.length) {
      s += rdata.substring(pos, +(len + pos))
      pos = len + pos
      len = rdata.charCodeAt(pos + 1)
    }
    return [ fqdn, s, ttl, ts, loc ]
  }

  fromBind (str) {
    // test.example.com  3600  IN  TXT  "...""
    const [ fqdn, ttl, c, type ] = str.split(/\s+/)
    return new this.constructor({
      class: c,
      type : type,
      name : fqdn,
      data : str.split(/\s+/).slice(4).map(s => s.replace(/^"|"$/g, '')).join(''),
      ttl  : parseInt(ttl, 10),
    })
  }

  /******  EXPORTERS   *******/
  toBind () {
    let data = this.get('data')
    if (data.length > 255) {
      // BIND croaks when any string in the TXT RR data is longer than 255
      data = data.match(/(.{1,255})/g).join('" "')
    }
    return `${this.getFields('common').map(f => this.get(f)).join('\t')}\t"${data}"\n`
  }

  toTinydns () {
    const rdata = TINYDNS.escapeOctal(new RegExp(/[\r\n\t:\\/]/, 'g'), this.get('data'))
    return `'${this.get('name')}:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = TXT
