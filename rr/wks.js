import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

const WELL_KNOWN_PORTS = {
  echo: 7,
  discard: 9,
  systat: 11,
  daytime: 13,
  netstat: 15,
  ftp_data: 20,
  ftp: 21,
  ssh: 22,
  telnet: 23,
  smtp: 25,
  time: 37,
  rlp: 39,
  nameserver: 42,
  nicname: 43,
  domain: 53,
  mtp: 57,
  bootps: 67,
  bootpc: 68,
  tftp: 69,
  gopher: 70,
  rje: 77,
  finger: 79,
  http: 80,
  link: 87,
  supdup: 95,
  hostnames: 101,
  iso_tsap: 102,
  csnet_ns: 105,
  pop_2: 109,
  pop3: 110,
  sunrpc: 111,
  auth: 113,
  sftp: 115,
  uucp_path: 117,
  nntp: 119,
  ntp: 123,
  netbios_ns: 137,
  netbios_dgm: 138,
  netbios_ssn: 139,
  imap: 143,
  sql_net: 150,
  snmp: 161,
  snmp_trap: 162,
  cmip_man: 163,
  cmip_agent: 164,
  xdmcp: 177,
  nextstep: 178,
  bgp: 179,
  prospero: 191,
  irc: 194,
  smux: 199,
  at_rtmp: 201,
  at_nbp: 202,
  at_echo: 204,
  at_zis: 206,
  qmtp: 209,
  z3950: 210,
  ipx: 213,
  imap3: 220,
  ulistproc: 372,
  https: 443,
  snpp: 444,
  microsoft_ds: 445,
  kpasswd: 464,
  urd: 465,
  saft: 487,
  isakmp: 500,
  exec: 512,
  biff: 512,
  login: 513,
  who: 513,
  cmd: 514,
  syslog: 514,
  printer: 515,
  talk: 517,
  ntalk: 518,
  route: 520,
  timed: 525,
  tempo: 526,
  courier: 530,
  netnews: 532,
  netwall: 533,
  uucp: 540,
  remotefs: 556,
  nntps: 563,
  ldap: 389,
}

export default class WKS extends RR {
  static typeName = 'WKS'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('WKS: address is required')
    if (!this.isIPv4(val)) this.throwHelp('WKS address must be IPv4')
    this.set('address', val)
  }

  setProtocol(val) {
    if (!val) this.throwHelp('WKS: protocol is required')
    const upper = typeof val === 'string' ? val.toUpperCase() : val
    if (!['TCP', 'UDP', 6, 17].includes(upper)) this.throwHelp('WKS protocol must be TCP or UDP')
    this.set('protocol', upper)
  }

  setBitMap(val) {
    this.set('bit map', val ?? '')
  }

  getDescription() {
    return 'Well Known Service'
  }

  getTags() {
    return ['obsolete']
  }

  getRdataFields(arg) {
    return ['address', 'protocol', 'bit map']
  }

  getRFCs() {
    return [883, 1035]
  }

  getTypeId() {
    return 11
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'WKS',
      address: '192.0.2.1',
      protocol: 'TCP',
      'bit map': 'ftp smtp',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  WKS 192.168.1.1 TCP ftp smtp
    const parts = bindline.split(/\s+/)
    const [owner, ttl, c, type, address, protocol] = parts
    return new WKS({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      address,
      protocol,
      'bit map': parts.slice(6).join(' ').trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')

    const binary = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))
    const address = [binary[0], binary[1], binary[2], binary[3]].join('.')
    const protoNum = binary[4]
    const protoMap = { 6: 'TCP', 17: 'UDP' }
    const protocol = protoMap[protoNum] ?? protoNum
    const bitmap = new TextDecoder().decode(binary.subarray(5))

    return new WKS({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'WKS',
      address,
      protocol,
      'bit map': bitmap,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const address = [...rdata.subarray(0, 4)].join('.')
    const protoNum = rdata[4]
    const protoMap = { 6: 'TCP', 17: 'UDP' }
    const protocol = protoMap[protoNum] ?? String(protoNum)
    const PORT_NAMES = Object.fromEntries(Object.entries(WELL_KNOWN_PORTS).map(([k, v]) => [v, k]))
    const bitmap = rdata.subarray(5)
    const ports = []
    for (let i = 0; i < bitmap.length; i++) {
      for (let bit = 0; bit < 8; bit++) {
        if (bitmap[i] & (0x80 >> bit)) {
          const port = i * 8 + bit
          ports.push(PORT_NAMES[port] ?? String(port))
        }
      }
    }
    return new WKS({
      owner,
      ttl,
      class: cls,
      type: 'WKS',
      address,
      protocol,
      'bit map': ports.join(' '),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    const protoMap = { TCP: 6, UDP: 17, 6: 6, 17: 17 }
    const protoNum = protoMap[this.get('protocol')]

    return this.getTinydnsGeneric(
      TINYDNS.ipv4toOctal(this.get('address')) +
        TINYDNS.UInt8toOctal(protoNum) +
        TINYDNS.escapeOctal(dataRe, this.get('bit map')),
    )
  }

  getWireRdata() {
    const protoMap = { TCP: 6, UDP: 17, 6: 6, 17: 17 }
    const addrBytes = this.get('address').split('.').map(Number)
    const protoNum = protoMap[this.get('protocol')]

    const portNums = this.get('bit map')
      .trim()
      .split(/\s+/)
      .map((s) => {
        if (/^\d+$/.test(s)) return parseInt(s, 10)
        return WELL_KNOWN_PORTS[s.toLowerCase()]
      })
      .filter((p) => p !== undefined)

    if (portNums.length === 0) return new Uint8Array([...addrBytes, protoNum])

    const maxPort = Math.max(...portNums)
    const bitmapLen = Math.floor(maxPort / 8) + 1
    const bitmap = new Uint8Array(bitmapLen)
    for (const port of portNums) bitmap[Math.floor(port / 8)] |= 0x80 >> (port % 8)

    const result = new Uint8Array(5 + bitmapLen)
    result.set(addrBytes)
    result[4] = protoNum
    result.set(bitmap, 5)
    return result
  }
}
