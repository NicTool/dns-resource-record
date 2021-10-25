
const RR      = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class URI extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 256)

    this.setPriority(opts?.priority)
    this.setWeight(opts?.weight)
    this.setTarget(opts?.target)
  }

  /****** Resource record specific setters   *******/
  setPriority (val) {
    if (!this.is16bitInt('URI', 'priority', val)) return

    this.set('priority', val)
  }

  setWeight (val) {
    if (!this.is16bitInt('URI', 'weight', val)) return

    this.set('weight', val)
  }

  setTarget (val) {
    if (!val) throw new Error('URI: target is required')

    this.set('target', val)
  }

  /******  IMPORTERS   *******/
  fromTinydns () {
    //
  }

  fromBind () {
    //
  }

  /******  MISC   *******/
  getRFCs () {
    return [ 7553 ]
  }

  /******  EXPORTERS   *******/
  toBind () {
    const fields = [ 'name', 'ttl', 'class', 'type', 'priority', 'weight' ] // 'target'
    return `${fields.map(f => this.get(f)).join('\t')}\t"${this.get('target')}"\n`
  }

  toTinydns () {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    let rdata = ''

    for (const e of [ 'priority', 'weight' ]) {
      rdata += TINYDNS.UInt16toOctal(this.get(e))
    }

    rdata += TINYDNS.escapeOctal(dataRe, this.get('target'))
    return `:${this.get('name')}:256:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = URI
