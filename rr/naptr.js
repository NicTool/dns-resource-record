
const RR = require('./index')

class NAPTR extends RR {
  constructor (obj) {
    super(obj)

    this.order(obj?.order)
    this.preference(obj?.preference)
    this.flags(obj?.flags)
    this.service(obj?.service)
  }

  order (val) {
    if (!this.is16bitInt('NAPTR', 'order', val)) return

    this.set('order', val)
  }

  preference (val) {
    if (!this.is16bitInt('NAPTR', 'preference', val)) return
    this.set('preference', val)
  }

  flags (val) {
    if (![ 'S', 'A', 'U', 'P' ].includes(val))
      throw new Error (`NAPTR flags are invalid: RFC 2915`)

    this.set('flags', val)
  }

  service (val) {
    this.set('service', val)
  }
}

module.exports = NAPTR
