
const net = require('net')

const RR = require('./index').RR

class A extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 1)

    this.setAddress(opts.address)
  }

  /****** Resource record specific setters   *******/
  setAddress (val) {
    if (!val) throw new Error('A: address is required')
    if (!net.isIPv4(val)) throw new Error('A address must be IPv4')
    this.set('address', val)
  }

  getRFCs () {
    return [ 1035 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns () {
    // A          =>  + fqdn : ip : ttl:timestamp:lo
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
    return `+${this.get('name')}:${this.get('address')}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = A