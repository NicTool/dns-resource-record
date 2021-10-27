
const RR = require('./index').RR

class HINFO extends RR {
  constructor (opts) {
    super(opts)

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

    this.set('id', 13)
    this.setCpu(opts?.cpu)
    this.setOs(opts?.os)
  }

  /****** Resource record specific setters   *******/
  setCpu (val) {
    if (val.length > 255) throw new Error('HINFO cpu cannot exceed 255 chars')
    this.set('cpu', val)
  }

  setOs (val) {
    if (val.length > 255) throw new Error('HINFO os cannot exceed 255 chars')
    this.set('os', val)
  }

  getFields () {
    return [ 'name', 'ttl', 'class', 'type', 'cpu', 'os' ]
  }

  getRFCs () {
    return [ 8482 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // HINFO via generic, :fqdn:n:rdata:ttl:timestamp:lo
  }

  fromBind () {
  }

  /******  EXPORTERS   *******/
  toBind () {
    const quoted = [ 'cpu', 'os' ]
    return `${this.getFields().map(f => quoted.includes(f) ? this.getQuoted(f) : this.get(f)).join('\t')}\n`
  }

  toTinydns () {
  }
}

module.exports = HINFO
