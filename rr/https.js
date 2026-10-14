import RR from '../rr.js'

import * as WIRE from '../lib/wire.js'

export default class HTTPS extends RR {
  static typeName = 'HTTPS'
  static typeId = 65
  static RFCs = [9460]
  static tags = ['common']
  static rdataFields = [
    ['priority', 'u16'],
    ['target name', 'fqdn'],
    ['params', 'svcparams'],
  ]

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('HTTPS', 'priority', val)
    // RFC 9460 §2.4.2
    if (val === 0 && this.get('params')) this.throwHelp(`HTTPS: AliasMode (priority 0) takes no params`)
    this.set('priority', val)
  }

  setTargetName(val) {
    if (!val) this.throwHelp('HTTPS: target name is required')
    this.isFullyQualified('HTTPS', 'target name', val)
    this.isValidName('HTTPS', 'target name', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target name', this.lowercaseName(val))
  }

  setParams(val) {
    this.setTypedValue('svcparams', 'params', val)
  }

  getDescription() {
    return 'HTTP Semantics'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HTTPS',
      priority: 1,
      'target name': 'example.com.',
      params: 'alpn="h2,h3"',
    }
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/

  getWireRdata() {
    const targetBytes = this.wirePackDomain(this.get('target name'))
    const paramsBytes = WIRE.svcParamsToWire(this.get('params'))
    const result = new Uint8Array(2 + targetBytes.length + paramsBytes.length)
    new DataView(result.buffer).setUint16(0, this.get('priority'))
    result.set(targetBytes, 2)
    result.set(paramsBytes, 2 + targetBytes.length)
    return result
  }
}
