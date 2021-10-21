
const sprintf = require('sprintf-js').sprintf

const RR = require('./index')

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

  escapeOct (str) {
    let escaped = ''
    str.match(/(.{1})/g).map(c => {
      escaped += /[\r\n\t:\\/]/.test(c) ? sprintf('\\%03o', c.charCodeAt(0)) : c
    })
    return escaped
  }

  toTinydns () {
    return `'${this.get('name')}:${this.escapeOct(this.get('address'))}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = TXT
