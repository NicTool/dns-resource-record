
const net = require('net')

const sprintf = require('sprintf-js').sprintf

const RR = require('./index').RR

class AAAA extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 28)

    this.setAddress(opts?.address)
  }

  /****** Resource record specific setters   *******/
  setAddress (val) {
    if (!val) throw new Error('AAAA: address is required')
    if (!net.isIPv6(val)) throw new Error('AAAA: address must be IPv6')

    this.set('address', val.toLowerCase()) // IETFs suggest only lower case
  }

  getRFCs () {
    return [ 3596 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns () {
    // GENERIC =>  :fqdn:28:rdata:ttl:timestamp:lo
    // AAAA       =>  3 fqdn : ip : x:ttl:timestamp:lo
    // AAAA,PTR   =>  6 fqdn : ip : x:ttl:timestamp:lo
  }

  fromBind () {
    //
  }

  /******  EXPORTERS   *******/
  toBind () {
    const fields = [ 'name', 'ttl', 'class', 'type', 'address' ]
    return `${fields.map(f => this.get(f)).join('\t')}\n`
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
