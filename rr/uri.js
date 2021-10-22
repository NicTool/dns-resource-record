
const RR = require('./index').RR

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
    const fields = [ 'name', 'ttl', 'class', 'type', 'priority', 'weight', 'target' ]
    return `${fields.map(f => this.get(f)).join('\t')}\n`
  }
}

module.exports = URI
