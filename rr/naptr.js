
const RR = require('./index')

class NAPTR extends RR {
  constructor (obj) {
    super(obj)

    this.setOrder(obj?.order)
    this.setPreference(obj?.preference)
    this.setFlags(obj?.flags)
    this.setService(obj?.service)
  }

  setOrder (val) {
    if (!this.is16bitInt('NAPTR', 'order', val)) return

    this.set('order', val)
  }

  setPreference (val) {
    if (!this.is16bitInt('NAPTR', 'preference', val)) return
    this.set('preference', val)
  }

  setFlags (val) {
    if (![ 'S', 'A', 'U', 'P' ].includes(val))
      throw new Error (`NAPTR flags are invalid: RFC 2915`)

    this.set('flags', val)
  }

  setService (val) {
    this.set('service', val)
  }
}

module.exports = NAPTR
