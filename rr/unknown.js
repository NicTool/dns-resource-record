import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'
import { bytesToHex, hexToBytes } from '../lib/binary.js'
import { assertWireRoundTrip } from '../lib/wire.js'

/**
 * An RR of unknown type (RFC 3597). The numeric type id lives on the instance
 * (type: 'TYPE731'), not the class, so UNKNOWN is not in index.js's classes
 * array / typeMap. Rdata is opaque: a lowercase hex string, '' for zero-length.
 *
 * - index.js exports classFor('TYPE731' | 'MX' | 731), which resolves to the
 *   implementing class and to UNKNOWN for resolvable types without one
 * - UNKNOWN.fromRR(rr) converts any RR to its generic representation;
 *   unknown.toRR(A) converts back through the class's wire codec
 * - a known type written in generic form is converted to its class, as
 *   RFC 3597 §5 requires: RR.A.fromBind('e.example. 3600 IN A \# 4 0a000001')
 *   returns an A record with address 10.0.0.1
 * - domain names embedded in rdata are normalized to lowercase, like every
 *   other name this library handles
 * - meta-types (OPT, TSIG, ...) are not blocked from the generic form, though
 *   RFC 3597 §2 says they should not travel this way
 * - MaraDNS export is 'RAW nnn' with unquoted \xNN escapes ('' when empty);
 *   tinydns and MaraDNS exports require class IN
 */
export default class UNKNOWN extends RR {
  static typeName = 'UNKNOWN'
  static typeId = undefined // per-instance, see getTypeId()
  static RFCs = [3597]
  static rdataFields = [['rdata', 'hex']]
  static tags = []

  constructor(opts) {
    if (opts !== null && opts?.type === undefined && opts?.typeId !== undefined)
      opts = { ...opts, type: `TYPE${opts.typeId}` }
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setType(t) {
    const generic = /^TYPE(\d+)$/i.exec(t ?? '')
    if (!generic || parseInt(generic[1], 10) > 65535)
      this.throwHelp(`UNKNOWN: type must be TYPE<0-65535> (RFC 3597), got: ${t}`)
    this.set('type', `TYPE${parseInt(generic[1], 10)}`)
  }

  setRdata(val) {
    if (val === undefined || val === null)
      this.throwHelp(`UNKNOWN: rdata is required (a hex string, '' for zero-length)`)
    if (typeof val !== 'string' || /[^0-9a-fA-F]/.test(val) || val.length % 2 !== 0)
      this.throwHelp(`UNKNOWN: rdata must be an even-length hex string`)
    this.set('rdata', val.toLowerCase())
  }

  getTypeId() {
    const t = this.get('type')
    if (t === undefined) this.throwHelp(`UNKNOWN: type is not set`)
    return parseInt(t.slice(4), 10)
  }

  getDescription() {
    return 'Unknown Resource Record (RFC 3597)'
  }

  getCanonical() {
    return {
      owner: 'a.example.',
      ttl: 3600,
      class: 'CLASS32',
      type: 'TYPE731',
      rdata: 'abcdef012345',
    }
  }

  /******  IMPORTERS   *******/

  fromBind() {
    this.throwHelp(`UNKNOWN: rdata must use the RFC 3597 generic form: \\# <length> <hex>`)
  }

  fromTinydns({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline)
    if (!/^\d+$/.test(typeId ?? '') || parseInt(typeId, 10) > 65535)
      this.throwHelp(`UNKNOWN: invalid tinydns type id: ${typeId}`)
    return new UNKNOWN({
      owner,
      ttl,
      timestamp,
      location,
      type: `TYPE${parseInt(typeId, 10)}`,
      rdata: bytesToHex(TINYDNS.octalRdataToBytes(rdata ?? '')),
    })
  }

  fromWire({ owner, cls, ttl, rdata, typeId }) {
    return new UNKNOWN({
      owner,
      ttl,
      class: cls,
      type: `TYPE${typeId}`,
      rdata: bytesToHex(rdata),
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    return hexToBytes(this.get('rdata'))
  }

  toBind(zone_opts) {
    const hex = this.get('rdata')
    const len = hex.length / 2
    return `${this.getPrefix(zone_opts)}\t\\# ${len}${len ? ' ' + hex : ''}\n`
  }

  /******  CONVERTERS   *******/

  // any RR instance -> its RFC 3597 generic representation
  static fromRR(rr) {
    return new UNKNOWN({
      owner: rr.get('owner'),
      ttl: rr.get('ttl'),
      class: rr.get('class'),
      timestamp: rr.get('timestamp'),
      location: rr.get('location'),
      type: `TYPE${rr.getTypeId()}`,
      rdata: bytesToHex(rr.getWireRdata()),
    })
  }

  // generic representation -> a concrete RR class instance
  toRR(RRClass) {
    if (RRClass.typeId !== undefined && RRClass.typeId !== this.getTypeId())
      this.throwHelp(`UNKNOWN: type id ${this.getTypeId()} does not match ${RRClass.typeName}`)
    const rdata = hexToBytes(this.get('rdata'))
    const rr = new RRClass(null).fromWire({
      owner: this.get('owner'),
      cls: this.get('class'),
      ttl: this.get('ttl'),
      rdata,
      typeId: this.getTypeId(),
    })
    assertWireRoundTrip(rr, rdata)
    return rr
  }
}
