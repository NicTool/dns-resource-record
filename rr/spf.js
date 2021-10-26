
const RR = require('./index').RR

const TINYDNS = require('../lib/tinydns')

class SPF extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 99)

    this.setData(opts?.data)
  }

  /****** Resource record specific setters   *******/
  setData (val) {
    this.set('data', val)
  }

  getRFCs () {
    return [ 1035 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns () {
    // SPF        =>
  }

  fromBind () {
    //
  }

  /******  EXPORTERS   *******/
  toBind () {
    let data = this.get('data')
    if (data.length > 255) {
      // BIND croaks when any string in the SPF RR data is longer than 255
      data = data.match(/(.{1,255})/g).join('" "')
    }
    const fields = [ 'name', 'ttl', 'class', 'type' ]
    return `${fields.map(f => this.get(f)).join('\t')}\t"${data}"\n`
  }

  toTinydns () {
    const rdata = TINYDNS.escapeOctal(new RegExp(/[\r\n\t:\\/]/, 'g'), this.get('data'))
    return `${this.get('name')}:99:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = SPF