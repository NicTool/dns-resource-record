import RR from '../rr.js'

export default class SVCB extends RR {
  static typeName = 'SVCB'
  static typeId = 64
  static RFCs = [9460]
  static rdataFields = [
    ['priority', 'u16'],
    ['target name', 'fqdn'],
    ['params', 'svcparams'],
  ]

  /****** Resource record specific setters   *******/
  setPriority(val) {
    const typeName = this.constructor.typeName
    this.is16bitInt(typeName, 'priority', val)
    // RFC 9460 §2.4.2
    if (val === 0 && this.get('params')) this.throwHelp(`${typeName}: AliasMode (priority 0) takes no params`)
    this.set('priority', val)
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
}
