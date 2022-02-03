
const RR      = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class URI extends RR {
  constructor (opts) {
    super(opts)

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

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
  fromTinydns (str) {
    // URI via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [ fqdn, n, rdata, ttl, ts, loc ] = str.substring(1).split(':')
    if (n != 256) throw new Error('URI fromTinydns, invalid n')

    return new this.constructor({
      type     : 'URI',
      name     : fqdn,
      priority : TINYDNS.octalToUInt16(rdata.substring(0, 8)),
      weight   : TINYDNS.octalToUInt16(rdata.substring(8, 16)),
      target   : TINYDNS.octalToChar(rdata.substring(16)),
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  URI  priority, weight, target
    const [ fqdn, ttl, c, type, priority, weight, target ] = str.split(/\s+/)
    return new this.constructor({
      class      : c,
      type       : type,
      name       : fqdn,
      priority: parseInt(priority, 10),
      weight     : parseInt(weight, 10),
      target     : target.replace(/^"|"$/g, ''),
      ttl        : parseInt(ttl, 10),
    })
  }

  /******  MISC   *******/
  getFields () {
    return [ 'name', 'ttl', 'class', 'type', 'priority', 'weight', 'target' ]
  }

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
