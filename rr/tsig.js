import RR from '../rr.js'
import * as BINARY from '../lib/binary.js'
import * as WIRE from '../lib/wire.js'

export default class TSIG extends RR {
  static typeName = 'TSIG'
  static typeId = 250
  static RFCs = [2845, 8945]
  static rdataFields = ['algorithm name', 'time signed', 'fudge', 'mac', 'original id', 'error', 'other']
  static errorNames = {
    NOERROR: 0,
    BADSIG: 16,
    BADKEY: 17,
    BADTIME: 18,
    BADMODE: 19,
    BADNAME: 20,
    BADALG: 21,
    BADTRUNC: 22,
    BADCOOKIE: 23,
  }

  /****** Resource record specific setters   *******/

  getDescription() {
    return 'Transaction Signature'
  }

  getCanonical() {
    return {
      owner: 'test.example.',
      ttl: 0,
      class: 'ANY',
      type: 'TSIG',
      'algorithm name': 'hmac-sha256.',
      'time signed': 1620650000,
      fudge: 300,
      mac: '3q2+7w==',
      'original id': 12345,
      error: 0,
      other: '',
    }
  }

  setClass(t) {
    if (t !== 'ANY') this.throwHelp('TSIG: Class is required to be ANY')
    this.set('class', t)
  }

  setTtl(t) {
    if (t !== 0) this.throwHelp('TSIG: TTL is required to be 0')
    this.set('ttl', t)
  }

  setAlgorithmName(val) {
    this.setTypedValue('fqdn', 'algorithm name', val)
  }

  setTimeSigned(val) {
    if (val === undefined) this.throwHelp(`TSIG: 'time signed' is required`)
    if (!Number.isInteger(val) || val < 0 || val >= 2 ** 48)
      this.throwHelp(`TSIG: 'time signed' must be a 48-bit integer`)
    this.set('time signed', val)
  }

  setFudge(val) {
    // 16-bit unsigned
    this.is16bitInt('TSIG', 'fudge', val)
    this.set('fudge', val)
  }

  setMac(val) {
    if ((val ?? '') !== '') this.isBase64('TSIG', 'mac', val)
    this.set('mac', val ?? '')
  }

  setOriginalId(val) {
    this.is16bitInt('TSIG', 'original id', val)
    this.set('original id', val)
  }

  setError(val) {
    this.is16bitInt('TSIG', 'error', val)
    this.set('error', val)
  }

  setOther(val) {
    if ((val ?? '') !== '') this.isBase64('TSIG', 'other', val)
    this.set('other', val ?? '')
  }

  /******  IMPORTERS   *******/

  fromBind({ owner, ttl, class: cls, rdata }) {
    // BIND presentation: alg time fudge mac-size mac original-id error other-len other.
    // MAC and Other are base64 that may span tokens, sized by the count before them.
    const words = rdata.map((t) => t.text)
    let i = 0
    const next = (field) => {
      if (i === words.length) throw new Error(`TSIG: missing rdata: ${field}`)
      return words[i++]
    }
    const int = (field) => {
      const word = next(field)
      if (!/^\d+$/.test(word)) throw new Error(`TSIG: ${field} must be an integer: ${word}`)
      return parseInt(word, 10)
    }
    const base64 = (field, size) => {
      // padded base64 is exactly 4 characters per started 3 bytes
      const want = 4 * Math.ceil(size / 3)
      let b64 = ''
      while (b64.length < want) b64 += next(field)
      const valid = b64.length === want && /^[A-Za-z0-9+/]*={0,2}$/.test(b64)
      if (!valid || BINARY.base64ToBytes(b64).length !== size)
        throw new Error(`TSIG: ${field} is not ${size} bytes of base64`)
      return b64
    }

    const algorithmName = next('algorithm name')
    const timeSigned = int('time signed')
    const fudge = int('fudge')
    const mac = base64('mac', int('mac size'))
    const originalId = int('original id')
    const errorWord = next('error')
    const error =
      TSIG.errorNames[errorWord.toUpperCase()] ??
      (/^\d+$/.test(errorWord) ? parseInt(errorWord, 10) : undefined)
    if (error === undefined) throw new Error(`TSIG: error must be an rcode name or an integer: ${errorWord}`)
    const other = base64('other', int('other len'))
    if (i < words.length) throw new Error(`TSIG: unexpected rdata: ${words.slice(i).join(' ')}`)

    return new TSIG({
      owner,
      ttl,
      class: cls,
      type: 'TSIG',
      'algorithm name': algorithmName,
      'time signed': timeSigned,
      fudge,
      mac,
      'original id': originalId,
      error,
      other,
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const { fqdn: algorithmName, end } = this.wireUnpackDomain(rdata, 0)
    const dv = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength)
    const { timeSigned, fudge, mac, originalId, error, other } = unpackTail(rdata, dv, end)
    return new TSIG({
      owner,
      ttl: 0,
      class: 'ANY',
      type: 'TSIG',
      'algorithm name': algorithmName,
      'time signed': timeSigned,
      fudge,
      mac,
      'original id': originalId,
      error,
      other,
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    const mac = this.get('mac')
    const other = this.get('other')
    return (
      [
        this.getPrefix(zone_opts),
        this.get('algorithm name'),
        this.get('time signed'),
        this.get('fudge'),
        BINARY.base64ToBytes(mac).length,
        mac,
        this.get('original id'),
        this.get('error'),
        BINARY.base64ToBytes(other).length,
        other,
      ]
        .filter((f) => f !== '')
        .join('\t') + '\n'
    )
  }

  getWireRdata() {
    const algWire = WIRE.wirePackDomain(this.get('algorithm name'))
    const macBytes = BINARY.base64ToBytes(this.get('mac'))
    const otherBytes = BINARY.base64ToBytes(this.get('other'))

    const bytes = new Uint8Array(algWire.length + 6 + 2 + 2 + macBytes.length + 2 + 2 + 2 + otherBytes.length)
    const dv = new DataView(bytes.buffer, bytes.byteOffset)
    let pos = 0

    bytes.set(algWire, pos)
    pos += algWire.length
    // RFC 8945 §4.2: Time Signed is 48 bits.
    dv.setUint16(pos, Math.floor(this.get('time signed') / 2 ** 32))
    dv.setUint32(pos + 2, this.get('time signed') % 2 ** 32)
    pos += 6
    dv.setUint16(pos, this.get('fudge'))
    pos += 2
    dv.setUint16(pos, macBytes.length)
    pos += 2
    bytes.set(macBytes, pos)
    pos += macBytes.length
    dv.setUint16(pos, this.get('original id'))
    pos += 2
    dv.setUint16(pos, this.get('error'))
    pos += 2
    dv.setUint16(pos, otherBytes.length)
    pos += 2
    bytes.set(otherBytes, pos)

    return bytes
  }
}

// RFC 8945 §4.2: the rdata after the algorithm name.
// The MAC and Other Len fields must account for every remaining byte.
function unpackTail(bytes, dv, pos) {
  const need = (n) => {
    if (pos + n > bytes.length) throw new Error(`TSIG: rdata is truncated at byte ${pos}`)
  }
  need(10)
  const timeSigned = dv.getUint16(pos) * 2 ** 32 + dv.getUint32(pos + 2)
  pos += 6
  const fudge = dv.getUint16(pos)
  const macSize = dv.getUint16(pos + 2)
  pos += 4
  need(macSize + 6)
  const mac = BINARY.bytesToBase64(bytes.subarray(pos, pos + macSize))
  pos += macSize
  const originalId = dv.getUint16(pos)
  const error = dv.getUint16(pos + 2)
  const otherLen = dv.getUint16(pos + 4)
  pos += 6
  need(otherLen)
  const other = BINARY.bytesToBase64(bytes.subarray(pos, pos + otherLen))
  if (pos + otherLen !== bytes.length)
    throw new Error(`TSIG: ${bytes.length - pos - otherLen} bytes after Other Data`)
  return { timeSigned, fudge, mac, originalId, error, other }
}
