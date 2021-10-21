
const RR = require('./index')

class URI extends RR {
  constructor (opts) {
    super(opts)

    this.priority(opts?.priority)
    this.weight(opts?.weight)
    this.target(opts?.target)
  }

  priority (val) {
    if (!this.is16bitInt('URI', 'priority', val)) return

    this.set('priority', val)
  }

  weight (val) {
    if (!this.is16bitInt('URI', 'weight', val)) return

    this.set('weight', val)
  }

  target (val) {
    if (!val) throw new Error('URI: target is required')

    this.set('target', val)
  }
}

module.exports = URI
