import RR from '../rr.js'

export default class SRV extends RR {
  static typeName = 'SRV'
  static typeId = 33
  static RFCs = [2782]
  static rdataFields = [
    ['priority', 'u16'],
    ['weight', 'u16'],
    ['port', 'u16'],
    ['target', 'fqdn'],
  ]
  static tags = ['common']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.setTypedValue('u16', 'priority', val)
  }

  setWeight(val) {
    this.setTypedValue('u16', 'weight', val)
  }

  setPort(val) {
    this.setTypedValue('u16', 'port', val)
  }

  setTarget(val) {
    this.setTypedValue('fqdn', 'target', val)
  }

  getDescription() {
    return 'Service'
  }

  getCanonical() {
    return {
      owner: '_imaps._tcp.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SRV',
      priority: 10,
      weight: 10,
      port: 993,
      target: 'mail.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns(opts) {
    if (opts.tinyline[0] === ':') return this.fromTinydnsWire(opts)

    // patched tinydns with S records
    const [fqdn, addr, port, pri, weight, ttl, ts, loc] = opts.tinyline.slice(1).split(':')
    return new SRV({
      owner: this.fromTinyFQDN(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SRV',
      priority: parseInt(pri, 10),
      weight: parseInt(weight, 10),
      port: parseInt(port, 10),
      target: this.fromTinyFQDN(addr),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }
}
