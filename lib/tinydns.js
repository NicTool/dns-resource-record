export const SPECIAL_CHARS = {
  '+': ['A'],
  '-': [undefined], // disabled RR
  '%': ['location'],
  '.': ['SOA', 'NS', 'A'],
  '&': ['NS', 'A'],
  '=': ['A', 'PTR'],
  '@': ['MX', 'A'],
  '#': ['comment'],
  "'": ['TXT'],
  '^': ['PTR'],
  C: ['CNAME'],
  Z: ['SOA'],
  ':': ['generic'],
  3: ['AAAA'],
  6: ['AAAA', 'PTR'],
  S: ['SRV'],
}

const octalRe = new RegExp(/\\(?:[1-7][0-7]{0,2}|[0-7]{2,3})/, 'g')

export function escapeOctal(re, str) {
  let escaped = ''
  str.split(/(.{1})/g).map((c) => {
    escaped += re.test(c) ? charToOctal(c) : c
  })
  return escaped
}

export function unescapeOctal(str) {
  return octalToChar(str)
}

export function octalToChar(str) {
  // relace instances of \NNN with ASCII
  return str.replace(octalRe, (o) => String.fromCharCode(parseInt(o.slice(1), 8)))
}

export function octalToHex(str) {
  // relace instances of \NNN with Hex
  return str.replace(octalRe, (o) => {
    // parseInt(n, 8) -> from octal to decimal
    //  .toString(16) -> decimal to hex
    return parseInt(o.slice(1), 8).toString(16).padStart(2, 0)
  })
}

export function octalToUInt8(str) {
  return parseInt(str.slice(1, 4), 8) & 0xff
}

export function octalToUInt16(str) {
  return (parseInt(str.slice(1, 4), 8) << 8) | parseInt(str.slice(5, 8), 8)
}

export function octalToUInt32(str) {
  const b0 = parseInt(str.slice(1, 4), 8)
  const b1 = parseInt(str.slice(5, 8), 8)
  const b2 = parseInt(str.slice(9, 12), 8)
  const b3 = parseInt(str.slice(13, 16), 8)
  return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0
}

export function packString(str) {
  return str
    .match(/(.{1,255})/g)
    .map((s) => `${UInt8toOctal(s.length)}${s}`)
    .join('')
}

export function unpackString(str) {
  const asBuf = Uint8Array.from(octalToChar(str.toString()), (c) => c.charCodeAt(0))
  const dec = new TextDecoder()
  const res = []
  let pos = 0
  let len
  while ((len = asBuf[pos])) {
    // encoded length byte
    pos++
    res.push(dec.decode(asBuf.subarray(pos, pos + len)))
    pos = +(pos + len)
    if (pos >= asBuf.length) break
  }
  return res
}

export function packDomainName(fqdn) {
  const labelRegEx = new RegExp(/[^A-Za-z0-9-.]/, 'g')

  // RFC 1035, 3.3 Standard RRs
  // The standard wire format for DNS names. (1 octet length + octets)
  let packed = ''
  fqdn.split('.').forEach((label) => {
    if (label === undefined || !label.length) return

    packed += UInt8toOctal(label.length)

    packed += escapeOctal(labelRegEx, label)
  })
  packed += '\\000' // terminates with a zero length label
  return packed
}

export function unpackDomainName(escaped) {
  let pos = 0
  let binaryLen = 0
  const labels = []

  // consume the next logical "byte" (char or octal escape)
  const getNextByte = () => {
    if (pos >= escaped.length) return null

    let value
    if (escaped[pos] === '\\') {
      value = parseInt(escaped.slice(pos + 1, pos + 4), 8)
      pos += 4
    } else {
      value = escaped.charCodeAt(pos++)
    }

    binaryLen++
    return value
  }

  let lengthByte
  while ((lengthByte = getNextByte()) && lengthByte !== 0) {
    let label = ''
    for (let i = 0; i < lengthByte; i++) {
      const char = getNextByte()
      if (char === null) break
      label += String.fromCharCode(char)
    }
    labels.push(label)
  }

  return [`${labels.join('.')}.`, pos, binaryLen]
}

export function packHex(str) {
  let r = ''
  for (let i = 0; i < str.length; i = i + 2) {
    // nibble off 2 hex bytes, encode to octal
    r += UInt8toOctal(parseInt(str.slice(i, i + 2), 16))
  }
  return r
}

export function charToOctal(c) {
  if (typeof c === 'number') return UInt8toOctal(c)

  return UInt8toOctal(c.charCodeAt(0))
}

export function UInt8toOctal(n) {
  if (n > 255) {
    throw new Error(
      `UInt8toOctal: value ${n} exceeds 255 — tinydns encoders require Latin-1/byte input (code points <= 0xFF)`,
    )
  }

  return `\\${parseInt(n, 10).toString(8).padStart(3, 0)}`
}

export function UInt16toOctal(n) {
  return UInt8toOctal((n >>> 8) & 0xff) + UInt8toOctal(n & 0xff)
}

export function UInt32toOctal(n) {
  return (
    UInt8toOctal((n >>> 24) & 0xff) +
    UInt8toOctal((n >>> 16) & 0xff) +
    UInt8toOctal((n >>> 8) & 0xff) +
    UInt8toOctal(n & 0xff)
  )
}

export function ipv4toOctal(ip) {
  return UInt32toOctal(ip.split`.`.reduce((int, value) => int * 256 + +value))
}

export function octalToIPv4(str) {
  const asInt = octalToUInt32(str)
  return [24, 16, 8, 0].map((n) => (asInt >> n) & 0xff).join('.')
}

export function ipv6toOctal(ip) {
  return packHex(ip.replace(/:/g, ''))
}

export function octalToIPv6(str) {
  return octalToHex(str)
    .match(/(.{4})/g)
    .join(':')
}

export function base64toOctal(str) {
  const binary = atob(str)
  let escaped = ''
  for (let i = 0; i < binary.length; i++) {
    const b = binary.charCodeAt(i)
    escaped += /[A-Za-z0-9\-.]/.test(binary[i]) ? binary[i] : UInt8toOctal(b)
  }
  return escaped
}

export function octalToBase64(str) {
  return btoa(octalToChar(str))
}

export function hexToBytes(hex) {
  return Uint8Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16))
}

export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function bytesToBase64(bytes) {
  return btoa([...bytes].map((b) => String.fromCharCode(b)).join(''))
}

export function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
}
