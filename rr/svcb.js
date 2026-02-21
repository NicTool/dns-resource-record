import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class SVCB extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('SVCB', 'priority', val)

    this.set('priority', val)
  }

  setTargetName(val) {
    // this.isFullyQualified('SVCB', 'target name', val)
    // this.isValidHostname('SVCB', 'target name', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target name', val.toLowerCase())
  }

  setParams(val) {
    // if (!val) throw new Error(`SVCB: params is required`)

    this.set('params', val)
  }

  getDescription() {
    return 'Service Binding'
  }

  getRdataFields(arg) {
    return ['priority', 'target name', 'params']
  }

  getRFCs() {
    return [9460]
  }

  getTypeId() {
    return 64
  }

  /******  IMPORTERS   *******/

  fromBind(opts) {
    // test.example.com  3600  IN  SVCB Priority TargetName Params
    // _8443._foo.api.example.com. 7200 IN SVCB 0 svc4.example.net.
    // svc4.example.net.  7200  IN SVCB 3 svc4.example.net. ( alpn="bar" port="8004" )
    const [owner, ttl, c, type, pri, fqdn] = opts.bindline.split(/\s+/)
    return new SVCB({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      priority: parseInt(pri, 10),
      'target name': fqdn,
      params: opts.bindline.split(/\s+/).slice(6).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.UInt16toOctal(this.get('priority')) +
        TINYDNS.packDomainName(this.get('target name')) +
        TINYDNS.escapeOctal(dataRe, this.get('params')),
    )
  }
}
