
const RR = require('./index')

class URI extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 256)

    this.setPriority(opts?.priority)
    this.setWeight(opts?.weight)
    this.setTarget(opts?.target)
  }

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

  getRFCs () {
    return [ 7553 ]
  }

  toBind () {
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\tURI\t${this.get('priority')}\t${this.get('weight')}\t${this.get('target')}\n`
  }
}

module.exports = URI
