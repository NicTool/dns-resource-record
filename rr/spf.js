
const RR = require('./index').RR

const TINYDNS = require('../lib/tinydns')

class SPF extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setData (val) {
    this.set('data', val)
  }

  getDescription () {
    return 'Sender Policy Framework'
  }

  getRdataFields (arg) {
    return [ 'data' ]
  }

  getRFCs () {
    return [ 4408, 7208 ]
  }

  getTypeId () {
    return 99
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // SPF via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [ fqdn, n, rdata, ttl, ts, loc ] = str.substring(1).split(':')
    if (n != 99) throw new Error('SPF fromTinydns, invalid n')

    return new this.constructor({
      type     : 'SPF',
      name     : fqdn,
      data     : TINYDNS.octalToChar(rdata),
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  SPF  "rdata"
    const [ fqdn, ttl, c, type ] = str.split(/\s+/)
    return new this.constructor({
      class: c,
      type : type,
      name : fqdn,
      data : str.split(/\s+/).slice(4).map(s => s.replace(/^"|"$/g, '')).join(' ').trim(),
      ttl  : parseInt(ttl, 10),
    })
  }

  /******  EXPORTERS   *******/
  toBind () {
    let data = this.get('data')
    if (data.length > 255) {
      // BIND croaks when any string in the SPF RR data is longer than 255
      data = data.match(/(.{1,255})/g).join('" "')
    }
    return `${this.getFields('common').map(f => this.get(f)).join('\t')}\t"${data}"\n`
  }

  toTinydns () {
    const rdata = TINYDNS.escapeOctal(new RegExp(/[\r\n\t:\\/]/, 'g'), this.get('data'))
    return `:${this.get('name')}:99:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = SPF
