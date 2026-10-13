import RR from '../rr.js'

import * as WIRE from '../lib/wire.js'

export default class SVCB extends RR {
  static typeName = 'SVCB'
  static typeId = 64
  static RFCs = [9460]
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
    this.is16bitInt('SVCB', 'priority', val)

    this.set('priority', val)
  }

  setTargetName(val) {
    if (!val) this.throwHelp('SVCB: target name is required')
    this.isFullyQualified('SVCB', 'target name', val)
    this.isValidName('SVCB', 'target name', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target name', this.lowercaseName(val))
  }

  setParams(val) {
    this.setTypedValue('svcparams', 'params', val)
  }

  getDescription() {
    return 'Service Binding'
  }

  getCanonical() {
    return {
      owner: '_8443._foo.api.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SVCB',
      priority: 1,
      'target name': 'svc4.example.net.',
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
