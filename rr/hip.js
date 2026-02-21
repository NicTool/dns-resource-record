import RR from '../rr.js'

export default class HIP extends RR {
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
      'public key': 'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA==',
      'rendezvous servers': '',
    }
  }

  /******  IMPORTERS   *******/
  fromBind(opts) {
    // owner  ttl  IN  HIP  pk-algorithm HIT public-key [rendezvous-server...]
    const parts = opts.bindline.split(/\s+/)
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
}
