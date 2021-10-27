
const RR = require('./index').RR

const TINYDNS = require('../lib/tinydns')

class TXT extends RR {
  constructor (opts) {
    super(opts)

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

    this.set('id', 16)
    this.setData(opts?.data)
  }

  /****** Resource record specific setters   *******/
  setData (val) {
    this.set('data', val)
  }

  getFields () {
    return [ 'name', 'ttl', 'class', 'type' ]
  }

  getRFCs () {
    return [ 1035 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    let fqdn, s, ttl, ts, loc
    // 'fqdn:s:ttl:timestamp:lo
    if (str[0] === "'") {
      [ fqdn, s, ttl, ts, loc ] = str.substring(1).split(':')
    }
    else {
      // TODO (see tinydns.pm unpack_txt)
      // generic: :fqdn:n:rdata:ttl:timestamp:location
      // [ fqdn, n, rdata, ttl, ts, loc ] = str.substring(1).split(':')
      // if (n != 16) throw new Error('TXT fromTinydns, invalid n')
      // rdata = TINYDNS.octalToChar(rdata)
      // s = ''
    }

    return new this.constructor({
      type     : 'TXT',
      name     : fqdn,
      data     : TINYDNS.octalToChar(s),
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
    let data = this.get('data')
    if (data.length > 255) {
      // BIND croaks when any string in the TXT RR data is longer than 255
      data = data.match(/(.{1,255})/g).join('" "')
    }
    return `${this.getFields().map(f => this.get(f)).join('\t')}\t"${data}"\n`
  }

  toTinydns () {
    const rdata = TINYDNS.escapeOctal(new RegExp(/[\r\n\t:\\/]/, 'g'), this.get('data'))
    return `'${this.get('name')}:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = TXT
