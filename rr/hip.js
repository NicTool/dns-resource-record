import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class HIP extends RR {
  static typeName = 'HIP'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPkAlgorithm(val) {
    if (val === undefined) this.throwHelp('HIP: pk algorithm is required')
    this.is8bitInt('HIP', 'pk algorithm', val)
    this.set('pk algorithm', val)
  }

  setHit(val) {
    if (!val) this.throwHelp('HIP: hit is required')
    this.set('hit', val)
  }

  setPublicKey(val) {
    if (!val) this.throwHelp('HIP: public key is required')
    this.set('public key', val)
  }

  setRendezvousServers(val) {
    this.set('rendezvous servers', val ?? '')
  }

  getDescription() {
    return 'Host Identity Protocol'
  }

  getRdataFields(arg) {
    return ['pk algorithm', 'hit', 'public key', 'rendezvous servers']
  }

  getRFCs() {
    return [8005]
  }

  getTypeId() {
    return 55
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HIP',
      'pk algorithm': 2,
      hit: '200100107B1A74DF365639CC39F1D578',
      'public key':
        'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA==',
      'rendezvous servers': '',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // HIP via generic, :fqdn:55:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 55) this.throwHelp('HIP fromTinydns, invalid n')

    const bytes = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))
    const hitLen = bytes[0]
    const pkAlgorithm = bytes[1]
    const pkLen = (bytes[2] << 8) | bytes[3]

    const hit = TINYDNS.bytesToHex(bytes.subarray(4, 4 + hitLen)).toUpperCase()
    const publicKey = TINYDNS.bytesToBase64(bytes.subarray(4 + hitLen, 4 + hitLen + pkLen))

    const rvsNames = []
    let pos = 4 + hitLen + pkLen
    while (pos < bytes.length) {
      const [name, newPos] = TINYDNS.unpackDomainName(
        [...bytes.subarray(pos)]
          .map((b) => (b < 32 || b > 126 ? TINYDNS.UInt8toOctal(b) : String.fromCharCode(b)))
          .join(''),
      )
      pos += newPos
      if (name !== '.') rvsNames.push(name)
    }

    return new HIP({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'HIP',
      'pk algorithm': pkAlgorithm,
      hit,
      'public key': publicKey,
      'rendezvous servers': rvsNames.join(' '),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // owner  ttl  IN  HIP  pk-algorithm HIT public-key [rendezvous-server...]
    const parts = bindline.split(/\s+/)
    const [owner, ttl, c, type, pkAlgorithm, hit, publicKey] = parts
    return new HIP({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      'pk algorithm': parseInt(pkAlgorithm, 10),
      hit,
      'public key': publicKey,
      'rendezvous servers': parts.slice(7).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    const rs = this.get('rendezvous servers')
    const rsPart = rs ? `\t${rs}` : ''
    return `${this.getPrefix(zone_opts)}\t${this.get('pk algorithm')}\t${this.get('hit')}\t${this.get('public key')}${rsPart}\n`
  }

  toTinydns() {
    const hitHex = this.get('hit')
    const hitBytes = TINYDNS.hexToBytes(hitHex)
    const pkBytes = TINYDNS.base64ToBytes(this.get('public key'))
    const rs = this.get('rendezvous servers')

    let rdata = ''
    rdata += TINYDNS.UInt8toOctal(hitBytes.length)
    rdata += TINYDNS.UInt8toOctal(this.get('pk algorithm'))
    rdata += TINYDNS.UInt16toOctal(pkBytes.length)
    for (const b of hitBytes) rdata += TINYDNS.UInt8toOctal(b)
    for (const b of pkBytes) rdata += TINYDNS.UInt8toOctal(b)
    if (rs) {
      for (const name of rs.split(/\s+/)) rdata += TINYDNS.packDomainName(name)
    }

    return this.getTinydnsGeneric(rdata)
  }
}
