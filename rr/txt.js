
const RR = require('./index')

const TINYDNS = require('../lib/tinydns')

class TXT extends RR {
  constructor (opts) {
    super(opts)

    this.address(opts?.address)
  }

  address (val) {
    this.set('address', val)
  }

  toBind () {
    let addr = this.get('address')
    if (addr.length > 255) {
      // BIND croaks when any string in the TXT RR address is longer than 255
      addr = addr.match(/(.{1,255})/g).join('" "')
    }
    return `${this.get('name')}  ${this.get('ttl')} ${this.get('class')}  ${this.get('type')} ${this.get('address')}\n`
  }

  toTinydns () {
    const rdata = TINYDNS.escapeOct(new RegExp(/[\r\n\t:\\/]/, 'g'), this.get('address'))
    return `'${this.get('name')}:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = TXT