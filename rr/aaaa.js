
const net = require('net')

const sprintf = require('sprintf-js').sprintf

const RR = require('./index')

class AAAA extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 28)

    this.setAddress(opts?.address)
  }

  setAddress (val) {
    if (!val) throw new Error('AAAA: address is required')
    if (!net.isIPv6(val)) throw new Error('AAAA: address must be IPv6')

    this.set('address', val.toLowerCase()) // IETFs suggest only lower case
  }

  getRFCs () {
    return [ 3596 ]
  }

  toBind () {
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\t${this.get('type')}\t${this.get('address')}\n`
  }

  toTinydns () {

    let val = this.get('address')

    const colons = val.match(/:/g)
    if (colons && colons.length < 7) {
      // console.log(`AAAA: restoring compressed colons`)
      val = val.replace(/::/, ':'.repeat(9 - colons.length))
    }

    // restore compressed leading zeros
    val = val.split(':').map(s => sprintf('%04s', s)).join('')

    // from AAAA notation (8 groups of 4 hex digits) to 16 escaped octals
    let rdata = ''
    for (var i = 0; i < 32; i = i+2) {
      // nibble off 2 hex bytes, encode to octal
      rdata += sprintf('\\%03o', parseInt(val.slice(i, i+2), 16))
    }

    return `:${this.get('name')}:28:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = AAAA
