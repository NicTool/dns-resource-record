
const RR = require('./index').RR

class LOC extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 29)

    this.setAddress(opts?.address)
  }

  /****** Resource record specific setters   *******/
  setAddress (val) {
    if (!val) throw new Error('LOC: address is required')

    // todo: validate this
    this.set('address', val)
  }

  getRFCs () {
    return [ 1876 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns () {
    //
  }

  fromBind () {
    //
  }

  /******  EXPORTERS   *******/
  toBind () {
    const fields = [ 'name', 'ttl', 'class', 'type', 'address' ]
    return `${fields.map(f => this.get(f)).join('\t')}\n`
  }
}

module.exports = LOC
