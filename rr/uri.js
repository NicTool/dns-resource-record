
const RR = require('./index')

class URI extends RR {
  constructor (opts) {
    super(opts)

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
}

module.exports = URI
